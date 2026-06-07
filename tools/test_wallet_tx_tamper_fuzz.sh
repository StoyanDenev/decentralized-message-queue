#!/usr/bin/env bash
# determ-wallet tx-tamper fuzz — validate-tx must reject EVERY single-field
# mutation of a validly-signed TRANSFER envelope.
#
# validate-tx is the offline tx-envelope gate: it recomputes the canonical
# signing_bytes (src/chain/block.cpp Transaction::signing_bytes), verifies the
# Ed25519 signature against the pubkey DERIVED from the `from` anon-address, and
# checks tx_hash == SHA-256(signing_bytes). Soundness of that gate rests on a
# simple property: NO field can be altered without invalidating the signature or
# the hash. This test asserts that property directly — sign a real TRANSFER, then
# mutate each consensus-bound field one at a time and confirm validate-tx FAILS
# (non-zero exit) on every mutation, while the untouched tx PASSES.
#
# This is the offline tamper-resistance complement to the round-trip tests
# (sign-anon-tx -> validate-tx happy path). Fully OFFLINE (no cluster).
# Run from repo root: bash tools/test_wallet_tx_tamper_fuzz.sh
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

T=test_wallet_tx_tamper_fuzz
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# Two fresh keypairs: A signs, B is the destination (+ a swap target).
"$W" account-create-batch --count 2 --out "$T/keys.json" >/dev/null 2>&1
PRIV_A=$($PY -c "import json,sys;print(json.load(open('$T/keys.json'))['accounts'][0]['privkey_hex'])")
ADDR_A=$($PY -c "import json,sys;print(json.load(open('$T/keys.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json,sys;print(json.load(open('$T/keys.json'))['accounts'][1]['address'])")
cat > "$T/k.json" <<EOF
{"address":"$ADDR_A","privkey_hex":"$PRIV_A"}
EOF

# Sign a real TRANSFER A -> B.
"$W" sign-anon-tx --keyfile "$T/k.json" --to "$ADDR_B" --amount 100 --fee 1 --nonce 0 --out "$T/tx.json" >/dev/null 2>&1
if [ ! -s "$T/tx.json" ]; then
  echo "  FAIL: sign-anon-tx did not produce a signed tx (cannot run fuzz)"
  echo "  FAIL: test_wallet_tx_tamper_fuzz"; exit 1
fi

echo "=== signed tx field set ==="
$PY -c "import json;print(sorted(json.load(open('$T/tx.json')).keys()))"

# Control: the untouched tx must validate.
"$W" validate-tx --tx-json "$T/tx.json" >/dev/null 2>&1
assert "$([ $? -eq 0 ] && echo true || echo false)" "control: untouched signed tx VALIDATES (exit 0)"

# mutate <field> <mode> [arg]: write a one-field-mutated copy to $T/m.json.
# Returns 0 if the field existed + was changed, 1 if the field was absent.
mutate() {
  $PY - "$T/tx.json" "$T/m.json" "$1" "$2" "${3:-}" <<'PY'
import json, sys
src, dst, field, mode, arg = sys.argv[1:6]
d = json.load(open(src))
# resolve signature field name variants
sigkey = 'signature' if 'signature' in d else ('sig' if 'sig' in d else None)
key = sigkey if field == 'SIG' else field
if key is None or key not in d:
    sys.exit(1)  # field absent -> skip
v = d[key]
if mode == 'incr':            # numeric +1 (accepts int or numeric string)
    d[key] = (int(v) + 1) if isinstance(v, int) else str(int(v) + 1)
elif mode == 'set':           # replace with arg verbatim
    d[key] = arg
elif mode == 'xorhex':        # flip the first hex byte of a hex string
    d[key] = ('%02x' % (int(v[:2], 16) ^ 0xff)) + v[2:]
elif mode == 'type':          # flip the type to a different valid value
    d[key] = ('STAKE' if v == 'TRANSFER' else (3 if v == 0 else 'TRANSFER'))
else:
    sys.exit(2)
json.dump(d, open(dst, 'w'))
sys.exit(0)
PY
}

reject() {  # field $1 mutated via mode $2 [arg $3] must be REJECTED by validate-tx
  local label="$1";
  if mutate "$1" "$2" "${3:-}"; then
    "$W" validate-tx --tx-json "$T/m.json" >/dev/null 2>&1
    assert "$([ $? -ne 0 ] && echo true || echo false)" "tamper($label) -> validate-tx REJECTS"
  else
    echo "  INFO: field '$label' absent in this tx shape — skipped"
  fi
}

echo
echo "=== every single-field mutation must be rejected ==="
reject amount  incr
reject fee     incr
reject nonce   incr
reject to      set  "$ADDR_A"      # redirect funds to the signer
reject from    set  "$ADDR_B"      # impersonate a different sender
reject type    type
reject SIG     xorhex             # flip a signature byte
reject hash    xorhex             # flip a tx_hash byte

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_wallet_tx_tamper_fuzz"; exit 0
else
  echo "  FAIL: test_wallet_tx_tamper_fuzz"; exit 1
fi
