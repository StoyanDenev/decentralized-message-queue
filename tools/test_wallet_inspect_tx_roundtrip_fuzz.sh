#!/usr/bin/env bash
# determ-wallet inspect-tx round-trip fuzz — OFFLINE.
#
# Hardens the READ-ONLY tx inspector by feeding it many randomly-built
# (but known-by-construction) signed TRANSFER envelopes and asserting the
# decoded fields EQUAL the exact inputs that produced them. The oracle is
# the known CLI input — NOT a reimplementation of any hash / signature /
# serialization algorithm.
#
# Pipeline per case (fully offline, no cluster / daemon):
#     sign-anon-tx  (builds + signs a canonical TRANSFER from CLI flags)
#         |  signed envelope JSON
#         v
#     inspect-tx --json  (decodes envelope -> {amount,fee,nonce,to,from,
#                          type,type_mnemonic,hash_match,...})
#
# Assertions per random case:
#   * decoded amount        == the --amount we passed
#   * decoded fee           == the --fee we passed
#   * decoded nonce         == the --nonce we passed
#   * decoded to            == the --to address we passed
#   * decoded from          == the keyfile (signer) anon-address
#   * decoded type          == 0  AND type_mnemonic == "TRANSFER"
#   * hash_match            == true  (envelope.hash recomputes correctly)
#
# Tamper leg (proves the inspector actually DETECTS corruption, not just
# echoes inputs): take one good envelope, XOR-flip the first byte of the
# stored `hash` field (a real mutation every time), re-inspect, and assert
# hash_match flips to false while computed_hash is UNCHANGED (the body the
# hash is computed over was not touched) and stored_hash now differs from
# computed_hash.
#
# Distinct from:
#   * test_wallet_inspect_tx.sh         — single happy path + hand-crafted
#                                         per-TxType payload decode table.
#   * test_wallet_tx_tamper_fuzz.sh     — validate-tx (signature gate),
#                                         not inspect-tx.
# This file is a >=20-case fixed-seed round-trip + hash-tamper fuzz on the
# inspect-tx decoder specifically.
#
# Fixed-seed RNG (Python random.seed) -> reproducible case set.
# Run from repo root: bash tools/test_wallet_inspect_tx_roundtrip_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
W="$DETERM_WALLET"

PY=python
command -v python >/dev/null 2>&1 || PY=python3

T="build/test_wallet_inspect_tx_roundtrip_fuzz.$$"
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0
fail_count=0
assert() {
  # assert <actual> <expected> <label>
  if [ "$1" = "$2" ]; then
    echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"
    fail_count=$((fail_count + 1))
  fi
}

NUM_CASES=24

# ── Provision signer + a small pool of destination addresses ────────────────
# Signer A signs every tx; --to rotates over B/C/D so the decoded `to`
# field actually varies across cases (not a constant the test can't tell
# apart from a hard-coded echo).
"$W" account-create-batch --count 4 --out "$T/keys.json" >/dev/null 2>&1
if [ ! -s "$T/keys.json" ]; then
  echo "  FAIL: account-create-batch produced no keys (cannot run fuzz)"
  echo "  FAIL: test_wallet_inspect_tx_roundtrip_fuzz"; exit 1
fi

# Per-account signer keyfile (canonical wallet shape).
$PY -c "
import json
d = json.load(open('$T/keys.json'))
json.dump(d['accounts'][0], open('$T/signer.json', 'w'))
"
ADDR_A=$($PY -c "import json; print(json.load(open('$T/keys.json'))['accounts'][0]['address'])")

# Generate the fixed-seed case table: each line = amount fee nonce to_index.
# random.seed makes the set fully reproducible run to run.
$PY -c "
import random
random.seed(1337)
n = $NUM_CASES
for _ in range(n):
    amount = random.randint(1, 2**53 - 1)   # >0 (sign-anon-tx rejects 0); within JSON-safe int range
    fee    = random.randint(0, 1_000_000)
    nonce  = random.randint(0, 2**32 - 1)
    to_idx = random.randint(1, 3)           # accounts[1..3] are the destinations
    print(amount, fee, nonce, to_idx)
" > "$T/cases.txt"

CASE_LINES=$(grep -c '' "$T/cases.txt")
assert "$CASE_LINES" "$NUM_CASES" "fixed-seed RNG produced $NUM_CASES cases"

echo
echo "=== Round-trip: sign-anon-tx -> inspect-tx, decoded fields == known inputs ==="
i=0
while read -r AMOUNT FEE NONCE TO_IDX; do
  [ -z "${AMOUNT:-}" ] && continue
  i=$((i + 1))

  TO_ADDR=$($PY -c "import json; print(json.load(open('$T/keys.json'))['accounts'][$TO_IDX]['address'])")

  SIGNED="$T/signed_$i.json"
  "$W" sign-anon-tx --keyfile "$T/signer.json" --to "$TO_ADDR" \
       --amount "$AMOUNT" --fee "$FEE" --nonce "$NONCE" \
       --out "$SIGNED" >/dev/null 2>&1
  if [ ! -s "$SIGNED" ]; then
    echo "  FAIL: case $i: sign-anon-tx produced no envelope (amount=$AMOUNT fee=$FEE nonce=$NONCE)"
    fail_count=$((fail_count + 1)); continue
  fi

  JOUT=$("$W" inspect-tx --tx-json "$SIGNED" --json 2>&1 | tr -d '\r')

  # Decode-vs-known oracle: compare each decoded field to the EXACT value we
  # passed in. Single python call emits an OK/MISMATCH verdict + a diag line.
  VERDICT=$(printf '%s' "$JOUT" | $PY -c "
import json, sys
d = json.loads(sys.stdin.read())
exp_amount = $AMOUNT
exp_fee    = $FEE
exp_nonce  = $NONCE
exp_to     = '$TO_ADDR'
exp_from   = '$ADDR_A'
checks = {
    'amount':        d.get('amount')        == exp_amount,
    'fee':           d.get('fee')           == exp_fee,
    'nonce':         d.get('nonce')         == exp_nonce,
    'to':            d.get('to')            == exp_to,
    'from':          d.get('from')          == exp_from,
    'type':          d.get('type')          == 0,
    'type_mnemonic': d.get('type_mnemonic') == 'TRANSFER',
    'hash_match':    d.get('hash_match')    is True,
}
bad = [k for k, ok in checks.items() if not ok]
if bad:
    print('MISMATCH ' + ','.join(bad))
else:
    print('OK')
")
  assert "$VERDICT" "OK" "case $i: decoded fields == inputs (amount=$AMOUNT fee=$FEE nonce=$NONCE to=accounts[$TO_IDX])"
done < "$T/cases.txt"

# ── Tamper leg: XOR-flip the stored hash, hash_match must flip false ────────
echo
echo "=== Tamper: XOR-flip stored hash byte -> hash_match flips to false ==="
GOOD="$T/signed_1.json"

# Baseline: the untouched envelope must verify, and capture computed_hash.
BASE=$("$W" inspect-tx --tx-json "$GOOD" --json 2>&1 | tr -d '\r')
BASE_MATCH=$(printf '%s' "$BASE" | $PY -c "import json,sys; print(str(json.load(sys.stdin)['hash_match']).lower())")
BASE_COMPUTED=$(printf '%s' "$BASE" | $PY -c "import json,sys; print(json.load(sys.stdin)['computed_hash'])")
assert "$BASE_MATCH" "true" "tamper baseline: untouched envelope hash_match=true"

# XOR-flip the first hex byte of the stored `hash` field (always a real change).
$PY -c "
import json
d = json.load(open('$GOOD'))
h = d['hash']
flipped = '%02x' % (int(h[:2], 16) ^ 0xff)
d['hash'] = flipped + h[2:]
json.dump(d, open('$T/tampered.json', 'w'))
"
# Capture the wallet's REAL exit code (write to file so $? is the exe's, not
# tr's in a pipeline) — inspect-tx is read-only: it must still exit 0 even on
# a hash mismatch.
"$W" inspect-tx --tx-json "$T/tampered.json" --json >"$T/tampered.out" 2>&1
T_RC=$?
assert "$T_RC" "0" "tamper: inspect-tx still exits 0 (read-only)"
TJ=$(tr -d '\r' < "$T/tampered.out")

T_MATCH=$(printf '%s' "$TJ" | $PY -c "import json,sys; print(str(json.load(sys.stdin)['hash_match']).lower())")
assert "$T_MATCH" "false" "tamper: hash_match flips to false"

# The hash is computed over the body, which we did NOT touch -> computed_hash
# must be identical to the baseline; only the stored hash diverges.
T_COMPUTED=$(printf '%s' "$TJ" | $PY -c "import json,sys; print(json.load(sys.stdin)['computed_hash'])")
assert "$T_COMPUTED" "$BASE_COMPUTED" "tamper: computed_hash unchanged (body untouched)"

T_DIVERGE=$(printf '%s' "$TJ" | $PY -c "
import json, sys
d = json.loads(sys.stdin.read())
print('yes' if d['stored_hash'] != d['computed_hash'] else 'no')
")
assert "$T_DIVERGE" "yes" "tamper: stored_hash now differs from computed_hash"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_wallet_inspect_tx_roundtrip_fuzz"; exit 0
else
  echo "  FAIL: test_wallet_inspect_tx_roundtrip_fuzz"; exit 1
fi
