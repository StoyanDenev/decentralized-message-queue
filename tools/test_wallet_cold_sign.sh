#!/usr/bin/env bash
# determ-wallet cold-sign CLI test.
#
# Exercises offline transaction signing for the air-gapped cold-wallet
# workflow. Cold-sign is the SIGN-only counterpart to tx-sign-verify
# (Round 17): it reads an unsigned tx JSON, signs with a keyfile's
# Ed25519 priv_seed using the chain's canonical signing_bytes scheme,
# and writes a signed envelope ready for hot-machine submission.
#
# Distinct from tx-sign-verify in that it:
#   * SIGNS (not verifies) — produces a fresh sig field
#   * Refuses to overwrite an existing sig (tx_already_signed)
#   * Refuses to sign when keyfile.address != tx.from
#     (keyfile_address_mismatch)
#   * Refuses to overwrite --out without --force (output_exists)
#   * Refuses stdout output by default (--allow-stdout opt-in)
#
# Assertions:
#   1.  Help line mentions cold-sign.
#   2.  cold-sign --help exits 0.
#   3.  Missing --tx-json: exit 1.
#   4.  Missing --priv-keyfile: exit 1.
#   5.  Missing both --out and --allow-stdout: exit 1.
#   6.  --tx-json pointing at nonexistent file: exit 1.
#   7.  --priv-keyfile pointing at nonexistent file: exit 1.
#   8.  Malformed tx JSON: exit 1.
#   9.  tx-JSON missing required field 'from': exit 1.
#  10.  Valid unsigned tx, valid keyfile, --out path: exit 0.
#  11.  Output file is created at the requested path.
#  12.  Output is one-line JSON status with status=ok.
#  13.  Status JSON carries tx_hash_hex (64 hex chars).
#  14.  Status JSON carries out (matches --out path).
#  15.  Signed tx file is a JSON object with type/from/to/amount/fee/
#       nonce/payload/sig/hash fields.
#  16.  Signed sig field is exactly 128 hex chars.
#  17.  Signed hash field is exactly 64 hex chars.
#  18.  Body fields preserved verbatim (from/to/amount/fee/nonce/payload).
#  19.  Sibling verifier (tx-sign-verify) accepts the signed envelope.
#  20.  Output file mode is 0600 (POSIX-only; on Windows MSYS reports
#       a different shape — skipped via uname check).
#  21.  Wrong keyfile (sig from key B against tx.from=A): refusal
#       exit 1 with reason=keyfile_address_mismatch.
#  22.  Tx already signed (re-running cold-sign on a signed file):
#       exit 1 with reason=tx_already_signed.
#  23.  Output exists + no --force: exit 1 with reason=output_exists.
#  24.  Output exists + --force: exit 0 (overwrite permitted).
#  25.  --allow-stdout without --out: signed JSON on stdout, exit 0.
#  26.  Stdout-emitted envelope parses + carries a sig field.
#  27.  Empty payload tx: signs successfully.
#  28.  Tx with sig field present as empty string is treated as unsigned
#       (signs successfully — empty slot is the canonical "unsigned"
#       shape some emitters produce).
#  29.  Tx with sig field present as 128 zeros is treated as unsigned
#       (signs successfully — same reasoning).
#  30.  Round-trip: the produced sig hex matches what Python-Ed25519
#       computes over the same signing_bytes (cross-binary sig parity).
#
# Run from repo root: bash tools/test_wallet_cold_sign.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_cold_sign.$$"
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

# Generate two fresh keypairs via account-create-batch.
"$WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
PRIV_A=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['privkey_hex'])" "$TMP/keys.json")
ADDR_A=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['address'])"     "$TMP/keys.json")
PUB_A="${ADDR_A#0x}"
PRIV_B=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][1]['privkey_hex'])" "$TMP/keys.json")
ADDR_B=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][1]['address'])"     "$TMP/keys.json")
PUB_B="${ADDR_B#0x}"

# Write per-account keyfiles (single-account shape, same as account-export).
$PY -c "
import json,sys
d = json.load(open(sys.argv[1]))
json.dump(d['accounts'][0], open(sys.argv[2],'w'))
json.dump(d['accounts'][1], open(sys.argv[3],'w'))
" "$TMP/keys.json" "$TMP/key_a.json" "$TMP/key_b.json"

# Helper: build an unsigned tx JSON (no sig field).
build_unsigned() {
    local out_path="$1" tx_type="$2" from="$3" to="$4" amount="$5" fee="$6" nonce="$7" payload_hex="$8"
    $PY -c "
import json, sys
out_path, tx_type, sender, recipient, amount, fee, nonce, payload_hex = sys.argv[1:]
doc = {
    'type':    int(tx_type),
    'from':    sender,
    'to':      recipient,
    'amount':  int(amount),
    'fee':     int(fee),
    'nonce':   int(nonce),
    'payload': payload_hex,
}
with open(out_path,'w') as f: json.dump(doc, f)
" "$out_path" "$tx_type" "$from" "$to" "$amount" "$fee" "$nonce" "$payload_hex"
}

echo "=== 1. Help text mentions cold-sign ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "cold-sign"; then
  echo "  PASS: help mentions cold-sign"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing cold-sign"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. cold-sign --help exits 0 ==="
set +e
"$WALLET" cold-sign --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "cold-sign --help exits 0"

echo
echo "=== 3. Missing --tx-json: exit 1 ==="
set +e
"$WALLET" cold-sign --priv-keyfile "$TMP/key_a.json" --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --tx-json returns 1"

echo
echo "=== 4. Missing --priv-keyfile: exit 1 ==="
build_unsigned "$TMP/tx1.json" 0 "$ADDR_A" "$ADDR_B" 1000 5 1 "deadbeef"
set +e
"$WALLET" cold-sign --tx-json "$TMP/tx1.json" --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --priv-keyfile returns 1"

echo
echo "=== 5. Missing both --out and --allow-stdout: exit 1 ==="
set +e
"$WALLET" cold-sign --tx-json "$TMP/tx1.json" --priv-keyfile "$TMP/key_a.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --out without --allow-stdout returns 1"

echo
echo "=== 6. --tx-json nonexistent file: exit 1 ==="
set +e
"$WALLET" cold-sign --tx-json "$TMP/nonexistent.json" --priv-keyfile "$TMP/key_a.json" --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--tx-json nonexistent returns 1"

echo
echo "=== 7. --priv-keyfile nonexistent file: exit 1 ==="
set +e
"$WALLET" cold-sign --tx-json "$TMP/tx1.json" --priv-keyfile "$TMP/nonexistent.json" --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--priv-keyfile nonexistent returns 1"

echo
echo "=== 8. Malformed tx JSON: exit 1 ==="
printf '{"type": 0, "from": "' > "$TMP/malformed.json"
set +e
"$WALLET" cold-sign --tx-json "$TMP/malformed.json" --priv-keyfile "$TMP/key_a.json" --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "malformed JSON returns 1"

echo
echo "=== 9. Missing required field 'from': exit 1 ==="
$PY -c "
import json
d = {'type':0,'to':'$ADDR_B','amount':1000,'fee':5,'nonce':1,'payload':''}
json.dump(d, open('$TMP/tx_no_from.json','w'))
"
set +e
"$WALLET" cold-sign --tx-json "$TMP/tx_no_from.json" --priv-keyfile "$TMP/key_a.json" --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing from field returns 1"

echo
echo "=== 10. Valid unsigned tx, valid keyfile, --out: exit 0 ==="
set +e
OUT=$("$WALLET" cold-sign --tx-json "$TMP/tx1.json" --priv-keyfile "$TMP/key_a.json" --out "$TMP/signed1.json" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "valid sign returns 0"

echo
echo "=== 11. Output file is created at the requested path ==="
if [ -f "$TMP/signed1.json" ]; then
  echo "  PASS: signed1.json exists"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: signed1.json missing"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 12. Status output is JSON with status=ok ==="
STATUS_JSON=$(echo "$OUT" | tail -n 1)
STATUS=$(echo "$STATUS_JSON" | $PY -c "import json,sys; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "parse_failed")
assert_eq "$STATUS" "ok" "status field is ok"

echo
echo "=== 13. Status JSON carries tx_hash_hex (64 hex chars) ==="
TX_HASH=$(echo "$STATUS_JSON" | $PY -c "import json,sys; print(json.load(sys.stdin)['tx_hash_hex'])" 2>/dev/null || echo "")
LEN=${#TX_HASH}
assert_eq "$LEN" "64" "tx_hash_hex is 64 hex chars"

echo
echo "=== 14. Status JSON carries 'out' equal to --out path ==="
OUT_FIELD=$(echo "$STATUS_JSON" | $PY -c "import json,sys; print(json.load(sys.stdin)['out'])" 2>/dev/null || echo "")
assert_eq "$OUT_FIELD" "$TMP/signed1.json" "out field matches --out path"

echo
echo "=== 15. Signed JSON has all expected fields ==="
MISSING=$($PY -c "
import json
d = json.load(open('$TMP/signed1.json'))
need = ['type','from','to','amount','fee','nonce','payload','sig','hash']
miss = [k for k in need if k not in d]
print(','.join(miss))
")
assert_eq "$MISSING" "" "all required fields present in signed JSON"

echo
echo "=== 16. sig field is exactly 128 hex chars ==="
SIG_LEN=$($PY -c "import json; print(len(json.load(open('$TMP/signed1.json'))['sig']))")
assert_eq "$SIG_LEN" "128" "sig is 128 hex chars"

echo
echo "=== 17. hash field is exactly 64 hex chars ==="
HASH_LEN=$($PY -c "import json; print(len(json.load(open('$TMP/signed1.json'))['hash']))")
assert_eq "$HASH_LEN" "64" "hash is 64 hex chars"

echo
echo "=== 18. Body fields preserved verbatim ==="
PRESERVED=$($PY -c "
import json
src = json.load(open('$TMP/tx1.json'))
out = json.load(open('$TMP/signed1.json'))
ok = all(src[k] == out[k] for k in ('type','from','to','amount','fee','nonce','payload'))
print('yes' if ok else 'no')
")
assert_eq "$PRESERVED" "yes" "body fields byte-identical"

echo
echo "=== 19. Sibling verifier accepts the signed envelope ==="
set +e
"$WALLET" tx-sign-verify --tx "$TMP/signed1.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "tx-sign-verify accepts cold-signed envelope"

echo
echo "=== 20. Output file mode is 0600 (POSIX) ==="
# On MSYS / Windows the chmod is a no-op; skip the strict-mode check there.
UNAME=$(uname -s 2>/dev/null || echo unknown)
case "$UNAME" in
    Linux|Darwin|FreeBSD|OpenBSD|NetBSD)
        MODE=$(stat -c '%a' "$TMP/signed1.json" 2>/dev/null || stat -f '%Lp' "$TMP/signed1.json" 2>/dev/null)
        assert_eq "$MODE" "600" "file mode is 0600"
        ;;
    *)
        echo "  SKIP: 0600 check (uname=$UNAME; POSIX-only assertion)"; pass_count=$((pass_count + 1))
        ;;
esac

echo
echo "=== 21. Wrong keyfile (keyfile_address_mismatch): exit 1 ==="
set +e
"$WALLET" cold-sign --tx-json "$TMP/tx1.json" --priv-keyfile "$TMP/key_b.json" --out "$TMP/sig_wrong.json" >/dev/null 2>&1
RC=$?
STDOUT_PORTION=$("$WALLET" cold-sign --tx-json "$TMP/tx1.json" --priv-keyfile "$TMP/key_b.json" --out "$TMP/sig_wrong2.json" 2>/dev/null)
set -e
assert_eq "$RC" "1" "wrong-keyfile returns 1"
assert_contains "$STDOUT_PORTION" "keyfile_address_mismatch" "reason JSON cites keyfile_address_mismatch"

echo
echo "=== 22. Tx already signed: exit 1 ==="
# Try to re-sign signed1.json — it now has a real sig field.
set +e
STDOUT_PORTION=$("$WALLET" cold-sign --tx-json "$TMP/signed1.json" --priv-keyfile "$TMP/key_a.json" --out "$TMP/sig_resign.json" 2>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "re-signing already-signed tx returns 1"
assert_contains "$STDOUT_PORTION" "tx_already_signed" "reason JSON cites tx_already_signed"

echo
echo "=== 23. Output exists + no --force: exit 1 ==="
# signed1.json exists from test 10.
set +e
STDOUT_PORTION=$("$WALLET" cold-sign --tx-json "$TMP/tx1.json" --priv-keyfile "$TMP/key_a.json" --out "$TMP/signed1.json" 2>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "existing --out without --force returns 1"
assert_contains "$STDOUT_PORTION" "output_exists" "reason JSON cites output_exists"

echo
echo "=== 24. Output exists + --force: exit 0 ==="
set +e
"$WALLET" cold-sign --tx-json "$TMP/tx1.json" --priv-keyfile "$TMP/key_a.json" --out "$TMP/signed1.json" --force >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "existing --out with --force returns 0"

echo
echo "=== 25. --allow-stdout: exit 0 ==="
# Use a brand-new tx (tx_resign would now be a re-sign attempt).
build_unsigned "$TMP/tx2.json" 0 "$ADDR_A" "$ADDR_B" 42 0 7 ""
set +e
STDOUT_BLOB=$("$WALLET" cold-sign --tx-json "$TMP/tx2.json" --priv-keyfile "$TMP/key_a.json" --allow-stdout 2>/dev/null)
RC=$?
set -e
assert_eq "$RC" "0" "--allow-stdout returns 0"

echo
echo "=== 26. Stdout-emitted envelope parses + has sig field ==="
STDOUT_SIG=$(echo "$STDOUT_BLOB" | $PY -c "
import json, sys
# stdout has the signed envelope on its only line (status goes to stderr).
d = json.loads(sys.stdin.read().strip())
print(len(d['sig']))
" 2>/dev/null || echo "parse_failed")
assert_eq "$STDOUT_SIG" "128" "stdout envelope sig is 128 hex chars"

echo
echo "=== 27. Empty payload tx signs successfully ==="
build_unsigned "$TMP/tx_empty_payload.json" 0 "$ADDR_A" "$ADDR_B" 100 0 2 ""
set +e
"$WALLET" cold-sign --tx-json "$TMP/tx_empty_payload.json" --priv-keyfile "$TMP/key_a.json" --out "$TMP/signed_empty.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "empty-payload tx signs"
# Also confirm the verifier accepts it (canonical signing_bytes parity).
set +e
"$WALLET" tx-sign-verify --tx "$TMP/signed_empty.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "verifier accepts empty-payload signed envelope"

echo
echo "=== 28. Empty-string sig field is treated as unsigned ==="
$PY -c "
import json
d = json.load(open('$TMP/tx_empty_payload.json'))
d['sig'] = ''
json.dump(d, open('$TMP/tx_emptysig.json','w'))
"
set +e
"$WALLET" cold-sign --tx-json "$TMP/tx_emptysig.json" --priv-keyfile "$TMP/key_a.json" --out "$TMP/signed_emptysig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "empty-string sig treated as unsigned"

echo
echo "=== 29. All-zero sig field is treated as unsigned ==="
$PY -c "
import json
d = json.load(open('$TMP/tx_empty_payload.json'))
d['sig'] = '0' * 128
json.dump(d, open('$TMP/tx_zerosig.json','w'))
"
set +e
"$WALLET" cold-sign --tx-json "$TMP/tx_zerosig.json" --priv-keyfile "$TMP/key_a.json" --out "$TMP/signed_zerosig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "all-zero sig treated as unsigned"

echo
echo "=== 30. Round-trip: wallet sig matches Python-Ed25519 sig over same signing_bytes ==="
# Build a fresh deterministic tx, sign with wallet, sign separately with
# Python Ed25519, and compare. Ed25519 is deterministic — two correct
# implementations over identical signing_bytes MUST produce byte-
# identical sigs.
build_unsigned "$TMP/tx_rt.json" 0 "$ADDR_A" "$ADDR_B" 500 1 3 "cafebabe"
"$WALLET" cold-sign --tx-json "$TMP/tx_rt.json" --priv-keyfile "$TMP/key_a.json" --out "$TMP/signed_rt.json" >/dev/null 2>&1
WALLET_SIG=$($PY -c "import json; print(json.load(open('$TMP/signed_rt.json'))['sig'])")
PYTHON_SIG=$($PY -c "
import struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex('$PRIV_A'))
# Reconstruct signing_bytes per src/chain/block.cpp Transaction::signing_bytes.
sb  = bytes([0])
sb += '$ADDR_A'.encode('utf-8') + b'\\x00'
sb += '$ADDR_B'.encode('utf-8') + b'\\x00'
sb += struct.pack('>Q', 500)
sb += struct.pack('>Q', 1)
sb += struct.pack('>Q', 3)
sb += bytes.fromhex('cafebabe')
print(priv.sign(sb).hex())
")
assert_eq "$WALLET_SIG" "$PYTHON_SIG" "wallet sig == Python Ed25519 sig (cross-binary parity)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet cold-sign"; exit 0
else
    echo "  FAIL: test_wallet_cold_sign"; exit 1
fi
