#!/usr/bin/env bash
# determ-wallet account-import-many — bulk-import N accounts test (B2 round 2).
#
# Exercises the bulk-import companion to `account-import`. Verifies the
# command produces one keyfile per input record, handles per-record errors
# gracefully (skipped duplicates, errored bad rows), and writes a summary
# array with the spec-shaped {address, keyfile_path, status, reason?}
# entries.
#
# Assertions (>= 6 required per spec; this wrapper ships 12):
#   1.  Help text mentions account-import-many.
#   2.  Empty input ([]) -> no keyfiles produced + summary file with empty array.
#   3.  3-record input -> 3 keyfiles produced.
#   4.  Each produced encrypted keyfile loadable via `keyfile-info`.
#   5.  Duplicate address in input -> second is "skipped" + reason mentions
#       duplicate.
#   6.  Invalid privkey_hex -> that record's status is "error" + reason
#       populated; other records still succeed.
#   7.  Encrypted output: wrong passphrase -> decrypt fails (exit 2);
#       right passphrase -> decrypt succeeds.
#   8.  Determinism: same input + same passphrase env -> same filenames
#       + summary structure byte-equal (excluding envelope ciphertext
#       which differs by design due to per-keyfile salt+nonce).
#   9.  --summary path written + readable + matches the spec shape.
#  10.  Address mismatch (address != seed-derived) -> error + reason.
#  11.  Named record produces <name>.keyfile filename.
#  12.  Missing --in / --out-dir -> exit 1 with diagnostic.
#
# Run from repo root: bash tools/test_wallet_account_import_many.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Use a worktree-rooted temp dir so the Windows native binary and Python
# (which doesn't understand MSYS /tmp paths) can both reach it.
TMP="$PROJECT_ROOT/.aim_test_$$"
mkdir -p "$TMP/out"
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

PY=python
command -v python >/dev/null 2>&1 || PY=python3

echo "=== 1. Help text mentions account-import-many ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "account-import-many"; then
  echo "  PASS: help mentions account-import-many"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing account-import-many"; fail_count=$((fail_count + 1))
fi

echo
echo "=== Setup: mint 3 fresh accounts via account-create-batch ==="
"$WALLET" account-create-batch --count 3 --out "$TMP/batch.json" >/dev/null 2>&1
RC=$?
if [ "$RC" -ne 0 ]; then
    echo "  FAIL: account-create-batch setup failed (rc=$RC)"; fail_count=$((fail_count + 1))
fi
# Build the canonical input array: array of {address, privkey_hex, name?}
# with the third record carrying a 'name' field so we exercise both
# naming branches in one input.
$PY -c "
import json, sys
src = json.load(open(r'$TMP/batch.json'))
recs = [{'address': a['address'], 'privkey_hex': a['privkey_hex']} for a in src['accounts']]
recs[2]['name'] = 'alice'
json.dump(recs, open(r'$TMP/input.json', 'w'), indent=2)
print('setup: recs[0].address =', recs[0]['address'])
print('setup: recs[2].name    =', recs[2]['name'])
"

echo
echo "=== 2. Empty input ([]) -> no keyfiles + empty summary ==="
echo '[]' > "$TMP/empty.json"
mkdir -p "$TMP/empty_out"
"$WALLET" account-import-many --in "$TMP/empty.json" --out-dir "$TMP/empty_out" --summary "$TMP/empty_summary.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on empty input"
# Count files in empty_out
N_FILES=$(ls "$TMP/empty_out" 2>/dev/null | wc -l | tr -d ' ')
assert_eq "$N_FILES" "0" "no keyfiles produced from empty input"
EMPTY_SUMMARY=$(cat "$TMP/empty_summary.json")
SUMMARY_LEN=$($PY -c "import json; print(len(json.load(open(r'$TMP/empty_summary.json'))))")
assert_eq "$SUMMARY_LEN" "0" "summary file is an empty array"

echo
echo "=== 3. 3-record input (plaintext) -> 3 keyfiles produced ==="
mkdir -p "$TMP/out_plain"
"$WALLET" account-import-many --in "$TMP/input.json" --out-dir "$TMP/out_plain" --summary "$TMP/sum_plain.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on 3-record import"
N_FILES=$(ls "$TMP/out_plain" 2>/dev/null | wc -l | tr -d ' ')
assert_eq "$N_FILES" "3" "3 keyfiles produced from 3-record input"
# Verify the named-record produced <name>.keyfile rather than <address>.keyfile
if [ -f "$TMP/out_plain/alice.keyfile" ]; then
    echo "  PASS: named record produced 'alice.keyfile'"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: named record did not produce 'alice.keyfile'"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 4. 3-record encrypted input -> each loadable via keyfile-info ==="
export DETERM_PASSPHRASE="test-batch-passphrase-strong-12345"
mkdir -p "$TMP/out_enc"
"$WALLET" account-import-many --in "$TMP/input.json" --out-dir "$TMP/out_enc" --passphrase-env DETERM_PASSPHRASE --summary "$TMP/sum_enc.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on encrypted 3-record import"
N_FILES=$(ls "$TMP/out_enc" 2>/dev/null | wc -l | tr -d ' ')
assert_eq "$N_FILES" "3" "3 encrypted keyfiles produced"
# keyfile-info on each — must succeed (exit 0) since they are the
# canonical DETERM-NODE-V1 + DWE1 shape.
INFO_OK=0
INFO_FAIL=0
for f in "$TMP/out_enc"/*.keyfile; do
    if "$WALLET" keyfile-info --in "$f" >/dev/null 2>&1; then
        INFO_OK=$((INFO_OK + 1))
    else
        INFO_FAIL=$((INFO_FAIL + 1))
    fi
done
assert_eq "$INFO_OK" "3" "keyfile-info succeeds on all 3 encrypted keyfiles"
assert_eq "$INFO_FAIL" "0" "keyfile-info failures = 0"

echo
echo "=== 5. Duplicate address -> 'skipped' with reason ==="
$PY -c "
import json
src = json.load(open(r'$TMP/input.json'))
dup = src + [src[0]]  # append duplicate of first record
json.dump(dup, open(r'$TMP/dup.json', 'w'), indent=2)
"
mkdir -p "$TMP/out_dup"
"$WALLET" account-import-many --in "$TMP/dup.json" --out-dir "$TMP/out_dup" --summary "$TMP/sum_dup.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on duplicate-containing input"
# Inspect the 4th summary record (index 3) — must be status=skipped.
DUP_STATUS=$($PY -c "import json; print(json.load(open(r'$TMP/sum_dup.json'))[3]['status'])")
assert_eq "$DUP_STATUS" "skipped" "duplicate entry has status='skipped'"
DUP_REASON=$($PY -c "import json; print(json.load(open(r'$TMP/sum_dup.json'))[3]['reason'])")
if echo "$DUP_REASON" | grep -qi "duplicate"; then
    echo "  PASS: duplicate reason mentions 'duplicate'"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: duplicate reason missing 'duplicate'"; fail_count=$((fail_count + 1))
fi
# And only 3 keyfiles, not 4.
N_FILES=$(ls "$TMP/out_dup" 2>/dev/null | wc -l | tr -d ' ')
assert_eq "$N_FILES" "3" "duplicate did not produce a 4th keyfile"

echo
echo "=== 6. Invalid privkey_hex -> 'error', others succeed ==="
$PY -c "
import json
src = json.load(open(r'$TMP/input.json'))
mixed = list(src) + [{'address': '0x' + '00' * 32, 'privkey_hex': 'zz' + '0' * 62}]
json.dump(mixed, open(r'$TMP/mixed.json', 'w'), indent=2)
"
mkdir -p "$TMP/out_mixed"
"$WALLET" account-import-many --in "$TMP/mixed.json" --out-dir "$TMP/out_mixed" --summary "$TMP/sum_mixed.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on mixed-validity input"
BAD_STATUS=$($PY -c "import json; print(json.load(open(r'$TMP/sum_mixed.json'))[3]['status'])")
assert_eq "$BAD_STATUS" "error" "bad-hex entry has status='error'"
BAD_REASON=$($PY -c "import json; d=json.load(open(r'$TMP/sum_mixed.json'))[3]; print(d.get('reason', ''))")
if [ -n "$BAD_REASON" ]; then
    echo "  PASS: bad-hex entry has populated reason"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: bad-hex entry missing reason"; fail_count=$((fail_count + 1))
fi
# First 3 still ok.
OK_COUNT=$($PY -c "import json; print(sum(1 for r in json.load(open(r'$TMP/sum_mixed.json')) if r['status']=='ok'))")
assert_eq "$OK_COUNT" "3" "first 3 records still status='ok' (bad row didn't poison the batch)"

echo
echo "=== 7. Encrypted output: wrong passphrase -> decrypt fails; right -> works ==="
ANY_ENC_FILE=$(ls "$TMP/out_enc"/*.keyfile 2>/dev/null | head -1)
if [ -z "$ANY_ENC_FILE" ]; then
    echo "  FAIL: no encrypted keyfile available for passphrase test"; fail_count=$((fail_count + 1))
else
    # Wrong passphrase — should exit 2 per keyfile-decrypt convention.
    export DETERM_WRONG_PASS="not-the-right-passphrase"
    set +e
    "$WALLET" keyfile-decrypt --in "$ANY_ENC_FILE" --passphrase-from env:DETERM_WRONG_PASS --out "$TMP/wrong.json" >/dev/null 2>&1
    WRONG_RC=$?
    set -e
    assert_eq "$WRONG_RC" "2" "wrong passphrase -> exit 2 (auth-style)"
    # Right passphrase — should exit 0 and produce a parseable plaintext file.
    "$WALLET" keyfile-decrypt --in "$ANY_ENC_FILE" --passphrase-from env:DETERM_PASSPHRASE --out "$TMP/right.json" >/dev/null 2>&1
    RIGHT_RC=$?
    assert_eq "$RIGHT_RC" "0" "right passphrase -> exit 0"
    HAS_PRIV_SEED=$($PY -c "import json; d=json.load(open(r'$TMP/right.json')); print('YES' if 'priv_seed' in d and len(d['priv_seed'])==64 else 'NO')")
    assert_eq "$HAS_PRIV_SEED" "YES" "decrypted keyfile has priv_seed (64 hex)"
fi

echo
echo "=== 8. Determinism: same input -> same filenames + summary structure ==="
mkdir -p "$TMP/out_det1" "$TMP/out_det2"
"$WALLET" account-import-many --in "$TMP/input.json" --out-dir "$TMP/out_det1" --passphrase-env DETERM_PASSPHRASE --summary "$TMP/sum_det1.json" >/dev/null 2>&1
"$WALLET" account-import-many --in "$TMP/input.json" --out-dir "$TMP/out_det2" --passphrase-env DETERM_PASSPHRASE --summary "$TMP/sum_det2.json" >/dev/null 2>&1
# Compare filename sets (sorted basenames).
FILES1=$(ls "$TMP/out_det1" | sort | tr '\n' ',')
FILES2=$(ls "$TMP/out_det2" | sort | tr '\n' ',')
assert_eq "$FILES1" "$FILES2" "deterministic: same filenames across runs"
# Compare summary structure (addresses + statuses match; basename of
# keyfile_path matches; ciphertext-bearing fields are NOT compared since
# envelope salt+nonce differ by design).
$PY -c "
import json, sys, os
s1 = json.load(open(r'$TMP/sum_det1.json'))
s2 = json.load(open(r'$TMP/sum_det2.json'))
assert len(s1) == len(s2), 'summary length mismatch'
for r1, r2 in zip(s1, s2):
    assert r1['address'] == r2['address'], 'address mismatch'
    assert r1['status']  == r2['status'],  'status mismatch'
    b1 = os.path.basename(r1['keyfile_path'].replace('\\\\', '/'))
    b2 = os.path.basename(r2['keyfile_path'].replace('\\\\', '/'))
    assert b1 == b2, f'basename mismatch: {b1} vs {b2}'
print('OK')
"
RC=$?
assert_eq "$RC" "0" "deterministic: summary structure matches across runs"

echo
echo "=== 9. --summary file readable + matches spec shape ==="
# Spec: array of {address, keyfile_path, status: 'ok'|'skipped'|'error', reason?}
$PY -c "
import json, re
s = json.load(open(r'$TMP/sum_plain.json'))
assert isinstance(s, list), 'summary must be a JSON array'
assert len(s) == 3, 'expected 3 entries'
for r in s:
    assert isinstance(r, dict), 'each entry must be an object'
    assert 'address' in r and isinstance(r['address'], str)
    assert 'keyfile_path' in r and isinstance(r['keyfile_path'], str)
    assert 'status' in r and r['status'] in {'ok','skipped','error'}
    if r['status'] != 'ok':
        assert 'reason' in r and r['reason'], 'non-ok entry must have reason'
    # Address shape check (ok entries): 0x + 64 hex
    if r['status'] == 'ok':
        assert re.match(r'^0x[0-9a-f]{64}\$', r['address']), 'bad address shape'
print('OK')
"
RC=$?
assert_eq "$RC" "0" "summary matches spec shape (address, keyfile_path, status, reason?)"

echo
echo "=== 10. Address/seed mismatch -> 'error' with reason ==="
$PY -c "
import json
src = json.load(open(r'$TMP/input.json'))
# Tamper with the address — flip one hex char.
addr = src[0]['address']
# Replace the LAST hex digit (which is a hex char) with one that's different
last = addr[-1]
new_last = 'a' if last != 'a' else 'b'
src[0]['address'] = addr[:-1] + new_last
json.dump([src[0]], open(r'$TMP/mismatch.json', 'w'), indent=2)
"
mkdir -p "$TMP/out_mm"
"$WALLET" account-import-many --in "$TMP/mismatch.json" --out-dir "$TMP/out_mm" --summary "$TMP/sum_mm.json" >/dev/null 2>&1
MM_STATUS=$($PY -c "import json; print(json.load(open(r'$TMP/sum_mm.json'))[0]['status'])")
assert_eq "$MM_STATUS" "error" "address/seed mismatch -> status='error'"
MM_REASON=$($PY -c "import json; print(json.load(open(r'$TMP/sum_mm.json'))[0]['reason'])")
if echo "$MM_REASON" | grep -qi "address"; then
    echo "  PASS: mismatch reason mentions 'address'"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: mismatch reason missing 'address'"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 11. Named record produces <name>.keyfile filename ==="
if [ -f "$TMP/out_plain/alice.keyfile" ]; then
    # And verify the keyfile content is the plaintext shape since
    # out_plain was emitted without --passphrase-env.
    HAS_ADDR=$($PY -c "
import json
d = json.load(open(r'$TMP/out_plain/alice.keyfile'))
print('YES' if 'address' in d and 'privkey_hex' in d else 'NO')
")
    assert_eq "$HAS_ADDR" "YES" "named keyfile has plaintext {address, privkey_hex}"
else
    echo "  FAIL: alice.keyfile not present in out_plain"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 12. Missing --in / --out-dir -> exit 1 with diagnostic ==="
set +e
ERR=$("$WALLET" account-import-many 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing required args"
assert_contains "$ERR" "required" "diagnostic mentions 'required'"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet account-import-many"; exit 0
else
    echo "  FAIL"; exit 1
fi
