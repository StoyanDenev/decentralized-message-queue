#!/usr/bin/env bash
# determ-wallet verify-equivocation — OFFLINE FA6 equivocation-evidence
# verifier (the EquivocationEvent two-sig proof).
#
# An EquivocationEvent records that ONE registered Ed25519 key signed TWO
# distinct 32-byte digests at the same height — the unambiguous proof the
# chain slashes the equivocator's full stake on. This command reproduces
# src/node/validator.cpp::check_equivocation_events byte-for-byte:
#   (1) digest_a != digest_b
#   (2) sig_a    != sig_b
#   (3) sig_a verifies over digest_a against --pubkey
#   (4) sig_b verifies over digest_b against --pubkey
# PROVEN ⟺ all four hold.
#
# Daemon-free: the equivocation evidence is synthesized locally with the
# wallet's own `message-sign` (two signs by the SAME key over TWO distinct
# messages give two valid sigs over two distinct SHA-256 commitments — a
# genuine equivocation). No cluster, no RPC, no chain-library link.
#
# Assertions:
#   1.  Help mentions verify-equivocation + the four-condition rule.
#   2.  Happy path: genuine two-sig evidence → PROVEN + exit 0.
#   3.  JSON output is well-formed and carries every expected field.
#   4.  Tamper sig_a (single hex flip) → NOT PROVEN, exit 2, sig_a_valid=false.
#   5.  Wrong --pubkey (a second key) → NOT PROVEN, exit 2 (both sigs fail).
#   6.  Same digest twice (sig over the SAME message) → NOT PROVEN, exit 2,
#       distinct_digests=false (the "signer signed the same thing twice"
#       non-equivocation case the validator explicitly rejects).
#   7.  Identical (digest,sig) on both sides → NOT PROVEN, exit 2,
#       distinct_sigs=false.
#   8.  --event with a bare EquivocationEvent JSON → PROVEN + echoes
#       equivocator/block_index metadata.
#   9.  --event with a Block JSON (equivocation_events[0]) → PROVEN.
#  10.  --event with --index selecting the second event → PROVEN.
#  11.  --event out-of-range --index → exit 1 (operator error, not auth).
#  12.  Missing --pubkey → exit 1 (key is ALWAYS operator-supplied).
#  13.  --event mutually exclusive with inline hex args → exit 1.
#  14.  Wrong-length --sig-a (hex) → exit 1 (args), not 2 (auth).
#  15.  Non-hex --digest-a → exit 1.
#  16.  Missing --event file → exit 1.
#
# Run from repo root: bash tools/test_wallet_verify_equivocation.sh
set -u
# pipefail so `OUT=$(cmd | tr -d '\r'); RC=$?` propagates the wallet's exit
# code (2 / 1) rather than always reporting tr's success.
set -o pipefail
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_verify_equivocation.$$"
mkdir -p "$TMP"
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

# ── Generate two fresh keypairs ───────────────────────────────────────────────
# account-create-batch emits {accounts:[{address, privkey_hex, ...}, ...]}.
# The 32-byte privkey_hex seed is what message-sign's --priv consumes; the
# address (minus 0x) is the 32-byte Ed25519 pubkey we pass as --pubkey.
"$WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
PRIV_A=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][0]['privkey_hex'])")
ADDR_A=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][0]['address'])")
PUB_A="${ADDR_A#0x}"
ADDR_B=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][1]['address'])")
PUB_B="${ADDR_B#0x}"

# ── Synthesize a genuine equivocation: SAME key, TWO distinct messages ────────
# message-sign emits signature_hex + message_hash_hex (the signed 32-byte
# SHA-256 commitment) + pubkey_hex. Two signs by the same priv over two
# distinct messages give two valid sigs over two distinct digests = the
# exact EquivocationEvent shape (one key, two conflicting signatures).
sign_msg() { # $1=msg ; sets DIGEST + SIG globals
  local out
  out=$("$WALLET" message-sign --priv "$PRIV_A" --message "$1" --domain-tag "EQ-TEST" --json 2>&1 | tr -d '\r')
  DIGEST=$($PY -c "import json,sys; print(json.loads('''$out''')['message_hash_hex'])")
  SIG=$($PY -c "import json,sys; print(json.loads('''$out''')['signature_hex'])")
}
sign_msg "block-7 candidate ALPHA"
DIG_A="$DIGEST"; SIG_A="$SIG"
sign_msg "block-7 candidate BRAVO"
DIG_B="$DIGEST"; SIG_B="$SIG"

# Sanity: the two digests + sigs must differ (else our test fixture is bad).
if [ "$DIG_A" = "$DIG_B" ] || [ "$SIG_A" = "$SIG_B" ]; then
  echo "  FAIL: fixture setup — two distinct messages produced identical digest/sig"
  exit 1
fi

echo "=== 1. Help mentions verify-equivocation + the four-condition rule ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "verify-equivocation"               "help lists verify-equivocation"
assert_contains "$H" "digest_a!=digest_b"                "help states the distinct-digest condition"
assert_contains "$H" "check_equivocation_events"         "help cites the validator gate it mirrors"

echo
echo "=== 2. Happy path: genuine two-sig evidence → PROVEN, exit 0 ==="
OUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" \
        --digest-a "$DIG_A" --sig-a "$SIG_A" \
        --digest-b "$DIG_B" --sig-b "$SIG_B" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "genuine evidence exits 0"
assert_contains "$OUT" "^PROVEN" "first line reports PROVEN"

echo
echo "=== 3. JSON output shape ==="
JOUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" \
        --digest-a "$DIG_A" --sig-a "$SIG_A" \
        --digest-b "$DIG_B" --sig-b "$SIG_B" --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "json mode exits 0 on PROVEN"
$PY - <<PY_EOF
import json, sys
r = json.loads('''$JOUT''')
needed = ['proven','distinct_digests','distinct_sigs','sig_a_valid',
          'sig_b_valid','pubkey_hex','digest_a_hex','digest_b_hex']
for k in needed:
    assert k in r, 'missing key: ' + k
assert r['proven'] is True, 'proven should be True'
assert r['distinct_digests'] is True
assert r['distinct_sigs'] is True
assert r['sig_a_valid'] is True
assert r['sig_b_valid'] is True
assert r['pubkey_hex'].lower() == '$PUB_A'.lower(), 'pubkey echo mismatch'
print('JSON_OK')
PY_EOF
JSON_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$JSON_OK" "true" "json carries {proven,distinct_digests,distinct_sigs,sig_a_valid,sig_b_valid,pubkey_hex,digest_a_hex,digest_b_hex}"

echo
echo "=== 4. Tamper sig_a → NOT PROVEN, exit 2, sig_a_valid=false ==="
FIRST=${SIG_A:0:1}
case "$FIRST" in
  0) NEW=1;; 1) NEW=2;; 2) NEW=3;; 3) NEW=4;; 4) NEW=5;; 5) NEW=6;;
  6) NEW=7;; 7) NEW=8;; 8) NEW=9;; 9) NEW=a;; a) NEW=b;; b) NEW=c;;
  c) NEW=d;; d) NEW=e;; e) NEW=f;; f) NEW=0;; *) NEW=1;;
esac
SIG_A_BAD="${NEW}${SIG_A:1}"
JOUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" \
        --digest-a "$DIG_A" --sig-a "$SIG_A_BAD" \
        --digest-b "$DIG_B" --sig-b "$SIG_B" --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "2" "tampered sig_a exits 2 (auth-style alert)"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven']      is False, 'proven must be False'
assert r['sig_a_valid'] is False, 'sig_a_valid must be False'
assert r['sig_b_valid'] is True,  'sig_b should still be valid'
print('TAMP_OK')
PY_EOF
TAMP_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$TAMP_OK" "true" "tampered sig_a: proven=false, sig_a_valid=false, sig_b_valid=true"

echo
echo "=== 5. Wrong --pubkey → NOT PROVEN, exit 2 (both sigs fail) ==="
JOUT=$("$WALLET" verify-equivocation --pubkey "$PUB_B" \
        --digest-a "$DIG_A" --sig-a "$SIG_A" \
        --digest-b "$DIG_B" --sig-b "$SIG_B" --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "2" "wrong pubkey exits 2"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven']      is False
assert r['sig_a_valid'] is False
assert r['sig_b_valid'] is False
print('WPK_OK')
PY_EOF
WPK_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$WPK_OK" "true" "wrong pubkey: both sig_*_valid=false"

echo
echo "=== 6. Same digest twice (signed same message) → NOT PROVEN ==="
# Signing the SAME message twice is the non-equivocation case the
# validator rejects: distinct_digests=false even though both sigs verify.
sign_msg "block-7 candidate ALPHA"   # identical message → identical digest
DIG_SAME="$DIGEST"; SIG_SAME="$SIG"
JOUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" \
        --digest-a "$DIG_A" --sig-a "$SIG_A" \
        --digest-b "$DIG_SAME" --sig-b "$SIG_SAME" --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "2" "same digest twice exits 2"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven']           is False, 'proven must be False'
assert r['distinct_digests'] is False, 'distinct_digests must be False'
# Both sigs DO verify — it is the distinctness rule (not the crypto) that
# fails, exactly as validator.cpp::check_equivocation_events distinguishes.
assert r['sig_a_valid']      is True
assert r['sig_b_valid']      is True
print('SAME_OK')
PY_EOF
SAME_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$SAME_OK" "true" "same message: distinct_digests=false (both sigs valid, but no conflict)"

echo
echo "=== 7. Identical (digest,sig) both sides → NOT PROVEN, distinct_sigs=false ==="
JOUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" \
        --digest-a "$DIG_A" --sig-a "$SIG_A" \
        --digest-b "$DIG_A" --sig-b "$SIG_A" --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "2" "identical pair exits 2"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven']        is False
assert r['distinct_sigs'] is False, 'distinct_sigs must be False'
print('IDENT_OK')
PY_EOF
IDENT_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$IDENT_OK" "true" "identical pair: distinct_sigs=false"

echo
echo "=== 8. --event with a bare EquivocationEvent JSON → PROVEN + metadata ==="
$PY - <<PY_EOF > "$TMP/event.json"
import json
print(json.dumps({
  "equivocator": "node-evil",
  "block_index": 7,
  "digest_a": "$DIG_A",
  "sig_a":    "$SIG_A",
  "digest_b": "$DIG_B",
  "sig_b":    "$SIG_B",
  "shard_id": 0,
  "beacon_anchor_height": 0
}))
PY_EOF
JOUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" --event "$TMP/event.json" --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--event EquivocationEvent exits 0 (PROVEN)"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven']      is True
assert r['equivocator'] == 'node-evil', 'equivocator metadata echoed'
assert r['block_index'] == 7,           'block_index metadata echoed'
print('EV_OK')
PY_EOF
EV_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$EV_OK" "true" "--event echoes equivocator + block_index from the record"

echo
echo "=== 9. --event with a Block JSON (equivocation_events[0]) → PROVEN ==="
$PY - <<PY_EOF > "$TMP/block.json"
import json
print(json.dumps({
  "index": 7,
  "transactions": [],
  "equivocation_events": [
    {"equivocator":"node-evil","block_index":7,
     "digest_a":"$DIG_A","sig_a":"$SIG_A",
     "digest_b":"$DIG_B","sig_b":"$SIG_B"}
  ]
}))
PY_EOF
OUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" --event "$TMP/block.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--event Block (events[0]) exits 0"
assert_contains "$OUT" "^PROVEN" "--event Block reports PROVEN"

echo
echo "=== 10. --event --index selecting the second event → PROVEN ==="
# Sign a third distinct message so events[1] is a fresh genuine pair.
sign_msg "block-9 candidate CHARLIE"
DIG_C="$DIGEST"; SIG_C="$SIG"
sign_msg "block-9 candidate DELTA"
DIG_D="$DIGEST"; SIG_D="$SIG"
$PY - <<PY_EOF > "$TMP/block2.json"
import json
print(json.dumps({
  "index": 9,
  "equivocation_events": [
    {"equivocator":"node-evil","block_index":7,
     "digest_a":"$DIG_A","sig_a":"$SIG_A","digest_b":"$DIG_B","sig_b":"$SIG_B"},
    {"equivocator":"node-evil2","block_index":9,
     "digest_a":"$DIG_C","sig_a":"$SIG_C","digest_b":"$DIG_D","sig_b":"$SIG_D"}
  ]
}))
PY_EOF
JOUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" --event "$TMP/block2.json" --index 1 --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--index 1 exits 0"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven'] is True
assert r['block_index'] == 9, 'should reflect events[1] block_index'
print('IDX_OK')
PY_EOF
IDX_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$IDX_OK" "true" "--index 1 selects the second event (block_index=9)"

echo
echo "=== 11. --event out-of-range --index → exit 1 ==="
"$WALLET" verify-equivocation --pubkey "$PUB_A" --event "$TMP/block.json" --index 5 >/dev/null 2>&1
RC=$?
assert_eq "$RC" "1" "out-of-range --index returns 1 (operator error)"

echo
echo "=== 12. Missing --pubkey → exit 1 ==="
"$WALLET" verify-equivocation \
        --digest-a "$DIG_A" --sig-a "$SIG_A" \
        --digest-b "$DIG_B" --sig-b "$SIG_B" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "1" "missing --pubkey returns 1 (key is always operator-supplied)"

echo
echo "=== 13. --event mutually exclusive with inline hex → exit 1 ==="
"$WALLET" verify-equivocation --pubkey "$PUB_A" --event "$TMP/event.json" \
        --digest-a "$DIG_A" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "1" "--event + inline hex returns 1"

echo
echo "=== 14. Wrong-length --sig-a → exit 1 (args, not auth) ==="
"$WALLET" verify-equivocation --pubkey "$PUB_A" \
        --digest-a "$DIG_A" --sig-a "abcd" \
        --digest-b "$DIG_B" --sig-b "$SIG_B" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "1" "short --sig-a returns 1, not 2"

echo
echo "=== 15. Non-hex --digest-a → exit 1 ==="
NONHEX=$($PY -c "print('z' * 64)")
"$WALLET" verify-equivocation --pubkey "$PUB_A" \
        --digest-a "$NONHEX" --sig-a "$SIG_A" \
        --digest-b "$DIG_B" --sig-b "$SIG_B" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "1" "non-hex --digest-a returns 1"

echo
echo "=== 16. Missing --event file → exit 1 ==="
OUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" --event "$TMP/nope.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "1" "missing --event file returns 1"
assert_contains "$OUT" "cannot open" "missing --event diagnostic mentions cannot open"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet verify-equivocation (offline FA6 two-sig proof verifier)"; exit 0
else
    echo "  FAIL: test_wallet_verify_equivocation"; exit 1
fi
