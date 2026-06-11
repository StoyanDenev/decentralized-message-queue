#!/usr/bin/env bash
# determ-wallet tx-sign-verify CLI test.
#
# Verifies the Ed25519 signature on a Transaction JSON file using the
# CHAIN's canonical signing_bytes scheme (NOT the off-chain
# domain-separated SHA-256 commitment used by message-sign / verify).
#
# signing_bytes layout (must match src/chain/block.cpp Transaction::signing_bytes):
#   [type: u8]
#   [from: utf8 bytes]
#   [0x00]                            # NUL after from
#   [to:   utf8 bytes]
#   [0x00]                            # NUL after to
#   [amount: u64 BIG-ENDIAN]
#   [fee:    u64 BIG-ENDIAN]
#   [nonce:  u64 BIG-ENDIAN]
#   [payload: raw bytes]
#
# The test constructs synthetic Transactions, signs them with Python's
# cryptography.hazmat Ed25519 implementation (independent of the wallet
# binary's verifier), and exercises the wallet's tx-sign-verify command
# in valid + tampered + error paths.
#
# Assertions:
#   1.  Help line mentions tx-sign-verify.
#   2.  Valid synthetic tx (TRANSFER) verifies: exit 0.
#   3.  Output includes the expected JSON fields (valid, tx_hash_hex,
#       computed_signing_bytes_sha256).
#   4.  --json output declares valid=true on a valid tx.
#   5.  tx_hash_hex equals SHA-256(signing_bytes) we computed in Python
#       (the wallet's hash matches the chain-canonical hash).
#   6.  tx_hash_hex equals computed_signing_bytes_sha256 (the two fields
#       are the same value, exposed under both names).
#   7.  Human (non-JSON) output prints "valid: true".
#   8.  Tampered amount: exit 2 (auth-style alert).
#   9.  Tampered fee: exit 2.
#  10.  Tampered nonce: exit 2.
#  11.  Tampered to-field: exit 2.
#  12.  Tampered from-field: exit 2.
#  13.  Tampered payload: exit 2.
#  14.  Tampered type byte: exit 2.
#  15.  Wrong pubkey (different key from same keypair pool): exit 2.
#  16.  Single-bit-flipped signature: exit 2.
#  17.  Missing --tx: exit 1.
#  18.  Missing --pubkey: exit 1.
#  19.  --tx pointing at nonexistent file: exit 1.
#  20.  --pubkey wrong length (< 64 chars): exit 1.
#  21.  --pubkey wrong length (> 64 chars): exit 1.
#  22.  --pubkey with non-hex characters: exit 1.
#  23.  Malformed JSON (truncated): exit 1.
#  24.  Missing required field 'type': exit 1.
#  25.  Missing required field 'from': exit 1.
#  26.  Missing required field 'sig': exit 1.
#  27.  Wrong sig length in JSON ('sig' is 64 chars not 128): exit 1.
#  28.  Empty payload (no payload bytes) verifies successfully.
#  29.  Empty 'from' field (anon-style empty literal, NUL-separated): still verifies.
#  30.  Large payload (~4KB random bytes) verifies successfully.
#  31.  Cross-binary independence: a sig from key A does NOT validate
#       under key B's pubkey (returns 2).
#
# Run from repo root: bash tools/test_wallet_tx_sign_verify.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Per-run scratch dir under build/ — same Windows-friendly pattern other
# wallet tests use (avoids MSYS /tmp path opaqueness for the native exe).
TMP="build/test_wallet_tx_sign_verify.$$"
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

# Generate two fresh keypairs via account-create-batch (these emit anon
# addresses + the 32-byte Ed25519 seeds as hex).
"$WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
PRIV_A=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['privkey_hex'])" "$TMP/keys.json")
ADDR_A=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['address'])"     "$TMP/keys.json")
PUB_A="${ADDR_A#0x}"
PRIV_B=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][1]['privkey_hex'])" "$TMP/keys.json")
ADDR_B=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][1]['address'])"     "$TMP/keys.json")
PUB_B="${ADDR_B#0x}"

# Python helper: build signing_bytes + sign with Ed25519, emit JSON tx.
# Outputs JSON to the path given by sys.argv[1].
build_tx() {
    local out_path="$1" tx_type="$2" from="$3" to="$4" amount="$5" fee="$6"
    local nonce="$7" payload_hex="$8" priv_hex="$9"
    $PY - "$out_path" "$tx_type" "$from" "$to" "$amount" "$fee" "$nonce" "$payload_hex" "$priv_hex" <<'PY_EOF'
import hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
out_path, tx_type, sender, recipient, amount, fee, nonce, payload_hex, priv_hex = sys.argv[1:]
tx_type = int(tx_type)
amount  = int(amount)
fee     = int(fee)
nonce   = int(nonce)
payload = bytes.fromhex(payload_hex)
# Reconstruct signing_bytes per src/chain/block.cpp Transaction::signing_bytes.
sb  = bytes([tx_type])
sb += sender.encode("utf-8") + b"\x00"
sb += recipient.encode("utf-8") + b"\x00"
sb += struct.pack(">Q", amount)   # u64 BIG-ENDIAN
sb += struct.pack(">Q", fee)
sb += struct.pack(">Q", nonce)
sb += payload
# Sign with the 32-byte Ed25519 seed.
seed = bytes.fromhex(priv_hex)
priv = Ed25519PrivateKey.from_private_bytes(seed)
sig  = priv.sign(sb)
tx_hash = hashlib.sha256(sb).digest()
doc = {
    "type":    tx_type,
    "from":    sender,
    "to":      recipient,
    "amount":  amount,
    "fee":     fee,
    "nonce":   nonce,
    "payload": payload.hex(),
    "sig":     sig.hex(),
    "hash":    tx_hash.hex(),
}
with open(out_path, "w") as f:
    json.dump(doc, f)
print(tx_hash.hex())
PY_EOF
}

echo "=== 1. Help text mentions tx-sign-verify ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "tx-sign-verify"; then
  echo "  PASS: help mentions tx-sign-verify"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing tx-sign-verify"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. Valid synthetic TRANSFER tx verifies ==="
EXPECTED_HASH=$(build_tx "$TMP/tx1.json" 0 "$ADDR_A" "$ADDR_B" 1000 5 1 "deadbeef" "$PRIV_A")
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx1.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "valid tx-sig verifies (exit 0)"

echo
echo "=== 3-4. --json output is parseable + has documented fields ==="
JSON_OUT=$("$WALLET" tx-sign-verify --tx "$TMP/tx1.json" --pubkey "$PUB_A" --json 2>&1 | tr -d '\r')
$PY - <<PY_EOF
import json, sys
d = json.loads('''$JSON_OUT''')
assert "valid" in d and isinstance(d["valid"], bool) and d["valid"] is True
assert "tx_hash_hex" in d and isinstance(d["tx_hash_hex"], str) and len(d["tx_hash_hex"]) == 64
assert "computed_signing_bytes_sha256" in d and isinstance(d["computed_signing_bytes_sha256"], str)
sys.exit(0)
PY_EOF
assert_eq "$?" "0" "--json doc has valid + tx_hash_hex + computed_signing_bytes_sha256"
VALID_FIELD=$(echo "$JSON_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['valid'])")
assert_eq "$VALID_FIELD" "True" "--json declares valid=true on a good sig"

echo
echo "=== 5. tx_hash_hex matches independently-computed SHA-256(signing_bytes) ==="
WALLET_HASH=$(echo "$JSON_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['tx_hash_hex'])")
assert_eq "$WALLET_HASH" "$EXPECTED_HASH" "wallet's tx_hash_hex matches Python-computed SHA-256(signing_bytes)"

echo
echo "=== 6. tx_hash_hex == computed_signing_bytes_sha256 ==="
CSB=$(echo "$JSON_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['computed_signing_bytes_sha256'])")
assert_eq "$CSB" "$WALLET_HASH" "computed_signing_bytes_sha256 mirrors tx_hash_hex"

echo
echo "=== 7. Human (non-JSON) output prints valid: true ==="
HUMAN_OUT=$("$WALLET" tx-sign-verify --tx "$TMP/tx1.json" --pubkey "$PUB_A" 2>&1 | tr -d '\r')
assert_contains "$HUMAN_OUT" "valid:" "human output has valid: line"
assert_contains "$HUMAN_OUT" "true" "human output declares valid: true"
assert_contains "$HUMAN_OUT" "tx_hash_hex:" "human output has tx_hash_hex: line"

echo
echo "=== 8. Tampered amount: exit 2 ==="
$PY - "$TMP/tx1.json" "$TMP/tx_tamp_amount.json" <<'PY_EOF'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
d = json.load(open(src))
d["amount"] = d["amount"] + 1   # mutate amount; sig no longer binds
json.dump(d, open(dst, "w"))
PY_EOF
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_tamp_amount.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "tampered amount returns 2 (auth-fail)"

echo
echo "=== 9. Tampered fee: exit 2 ==="
$PY - "$TMP/tx1.json" "$TMP/tx_tamp_fee.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["fee"] = d["fee"] + 1
json.dump(d, open(sys.argv[2], "w"))
PY_EOF
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_tamp_fee.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "tampered fee returns 2"

echo
echo "=== 10. Tampered nonce: exit 2 ==="
$PY - "$TMP/tx1.json" "$TMP/tx_tamp_nonce.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["nonce"] = d["nonce"] + 1
json.dump(d, open(sys.argv[2], "w"))
PY_EOF
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_tamp_nonce.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "tampered nonce returns 2"

echo
echo "=== 11. Tampered to-field: exit 2 ==="
$PY - "$TMP/tx1.json" "$TMP/tx_tamp_to.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
# Change one hex char in the 'to' address (still well-formed)
to = d["to"]
flipped = "0" if to[-1] != "0" else "1"
d["to"] = to[:-1] + flipped
json.dump(d, open(sys.argv[2], "w"))
PY_EOF
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_tamp_to.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "tampered to-field returns 2"

echo
echo "=== 12. Tampered from-field: exit 2 ==="
$PY - "$TMP/tx1.json" "$TMP/tx_tamp_from.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
fr = d["from"]
flipped = "0" if fr[-1] != "0" else "1"
d["from"] = fr[:-1] + flipped
json.dump(d, open(sys.argv[2], "w"))
PY_EOF
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_tamp_from.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "tampered from-field returns 2"

echo
echo "=== 13. Tampered payload: exit 2 ==="
$PY - "$TMP/tx1.json" "$TMP/tx_tamp_payload.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
p = d["payload"]
# Flip a payload byte (or extend if too short).
if not p:
    d["payload"] = "ff"
else:
    flipped = "0" if p[0] != "0" else "1"
    d["payload"] = flipped + p[1:]
json.dump(d, open(sys.argv[2], "w"))
PY_EOF
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_tamp_payload.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "tampered payload returns 2"

echo
echo "=== 14. Tampered type byte: exit 2 ==="
$PY - "$TMP/tx1.json" "$TMP/tx_tamp_type.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["type"] = (d["type"] + 1) & 0xFF
json.dump(d, open(sys.argv[2], "w"))
PY_EOF
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_tamp_type.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "tampered type byte returns 2"

echo
echo "=== 15. Wrong pubkey (key B verifying A's sig): exit 2 ==="
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx1.json" --pubkey "$PUB_B" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "wrong pubkey returns 2"

echo
echo "=== 16. Single-bit-flipped signature: exit 2 ==="
$PY - "$TMP/tx1.json" "$TMP/tx_tamp_sig.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
s = d["sig"]
flipped = "0" if s[0] != "0" else "1"
d["sig"] = flipped + s[1:]
json.dump(d, open(sys.argv[2], "w"))
PY_EOF
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_tamp_sig.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "bit-flipped sig returns 2"

echo
echo "=== 17. Missing --tx: exit 1 ==="
set +e
"$WALLET" tx-sign-verify --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --tx returns 1 (args error)"

echo
echo "=== 18. Missing --pubkey: exit 1 ==="
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx1.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --pubkey returns 1"

echo
echo "=== 19. --tx pointing at nonexistent file: exit 1 ==="
set +e
"$WALLET" tx-sign-verify --tx "$TMP/nonexistent.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--tx nonexistent file returns 1"

echo
echo "=== 20. --pubkey wrong length (too short): exit 1 ==="
set +e
ERR=$("$WALLET" tx-sign-verify --tx "$TMP/tx1.json" --pubkey "deadbeef" 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "--pubkey too short returns 1"
assert_contains "$ERR" "64 hex" "diagnostic mentions 64-hex requirement"

echo
echo "=== 21. --pubkey wrong length (too long): exit 1 ==="
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx1.json" --pubkey "${PUB_A}aa" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--pubkey too long returns 1"

echo
echo "=== 22. --pubkey with non-hex chars: exit 1 ==="
# Build a 64-char string of all 'z' characters (right length but not hex).
BAD_PUB=$($PY -c "print('z' * 64)")
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx1.json" --pubkey "$BAD_PUB" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--pubkey non-hex chars returns 1"

echo
echo "=== 23. Malformed JSON (truncated): exit 1 ==="
printf '{"type": 0, "from": "' > "$TMP/malformed.json"
set +e
"$WALLET" tx-sign-verify --tx "$TMP/malformed.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "malformed JSON returns 1"

echo
echo "=== 24. Missing 'type' field: exit 1 ==="
$PY - "$TMP/tx1.json" "$TMP/tx_no_type.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
del d["type"]
json.dump(d, open(sys.argv[2], "w"))
PY_EOF
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_no_type.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing type field returns 1"

echo
echo "=== 25. Missing 'from' field: exit 1 ==="
$PY - "$TMP/tx1.json" "$TMP/tx_no_from.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
del d["from"]
json.dump(d, open(sys.argv[2], "w"))
PY_EOF
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_no_from.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing from field returns 1"

echo
echo "=== 26. Missing 'sig' field: exit 1 ==="
$PY - "$TMP/tx1.json" "$TMP/tx_no_sig.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
del d["sig"]
json.dump(d, open(sys.argv[2], "w"))
PY_EOF
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_no_sig.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing sig field returns 1"

echo
echo "=== 27. Sig field wrong hex length: exit 1 ==="
$PY - "$TMP/tx1.json" "$TMP/tx_short_sig.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["sig"] = "deadbeef"   # 8 hex chars, not 128
json.dump(d, open(sys.argv[2], "w"))
PY_EOF
set +e
ERR=$("$WALLET" tx-sign-verify --tx "$TMP/tx_short_sig.json" --pubkey "$PUB_A" 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "wrong-length sig hex returns 1"
assert_contains "$ERR" "128 hex" "diagnostic mentions 128-hex requirement"

echo
echo "=== 28. Empty payload verifies ==="
build_tx "$TMP/tx_empty_payload.json" 0 "$ADDR_A" "$ADDR_B" 42 0 7 "" "$PRIV_A" >/dev/null
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_empty_payload.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "empty-payload tx verifies"

echo
echo "=== 29. Empty 'from' field (NUL-separated empty literal) verifies ==="
build_tx "$TMP/tx_empty_from.json" 0 "" "$ADDR_B" 100 0 1 "" "$PRIV_A" >/dev/null
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_empty_from.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "empty from-field tx (just NUL separator) verifies"

echo
echo "=== 30. Large payload (~4KB random hex) verifies ==="
BIG_HEX=$($PY -c "import secrets; print(secrets.token_hex(4096))")
build_tx "$TMP/tx_big.json" 0 "$ADDR_A" "$ADDR_B" 1 0 2 "$BIG_HEX" "$PRIV_A" >/dev/null
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_big.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "4KB-payload tx verifies"

echo
echo "=== 31. Cross-key independence (sig from A NOT valid under B's pubkey) ==="
build_tx "$TMP/tx_keyA.json" 0 "$ADDR_A" "$ADDR_B" 500 1 3 "cafebabe" "$PRIV_A" >/dev/null
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_keyA.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "sig from A validates under A's pubkey"
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx_keyA.json" --pubkey "$PUB_B" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "sig from A does NOT validate under B's pubkey"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet tx-sign-verify"; exit 0
else
    echo "  FAIL: test_wallet_tx_sign_verify"; exit 1
fi
