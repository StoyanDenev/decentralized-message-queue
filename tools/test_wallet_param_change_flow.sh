#!/usr/bin/env bash
# determ-wallet governance PARAM_CHANGE flow integration — composes the three
# governance commands end-to-end and asserts they agree on the wire format:
#   param-change-build  (assemble the unsigned body + signing preimage)
#   param-change-lint   (predict activation effectiveness)
#   param-change-verify (check the K-of-K keyholder multisig)
#
# This is the COMPOSITION test (distinct from the per-command tests): a layout
# change in param-change-build's payload would silently break lint AND verify;
# this catches that the three share one decoding. It also demonstrates the
# operator-critical complementarity of lint vs verify:
#   - a value with a bad width LINTS as INERT_BAD_WIDTH (will silently no-op at
#     activation) yet can still carry a perfectly VALID multisig — so verify
#     PASSes while lint FAILs. The two checks answer different questions and an
#     operator needs BOTH before submitting.
#
# Safe reference for the verify leg: an INDEPENDENT Ed25519 (Python pynacl,
# RFC 8032) plays the keyholders. FULLY OFFLINE (no cluster).
# Run from repo root: bash tools/test_wallet_param_change_flow.sh
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
if ! $PY -c "import nacl.signing" >/dev/null 2>&1; then
    echo "  SKIP: python pynacl not available (the independent Ed25519 reference)"; exit 0
fi

T=test_wallet_param_change_flow
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# Multisig assembler: decode the build payload, K keyholders sign the canonical
# sig_msg with an independent Ed25519, emit the assembled tx-json + keyholders.
cat > "$T/assemble.py" <<'PY'
import json, struct, sys, random
import nacl.signing
T, base_payload_hex, k, seed = sys.argv[1:5]
k = int(k); seed = int(seed); random.seed(seed)
p = bytes.fromhex(base_payload_hex); off = 0
nlen = p[off]; off += 1
name = p[off:off+nlen]; off += nlen
vlen = p[off] | (p[off+1] << 8); off += 2
value = p[off:off+vlen]; off += vlen
eff = p[off:off+8]; off += 8
sig_msg = bytes([nlen]) + name + bytes([vlen & 0xff, (vlen >> 8) & 0xff]) + value + eff
prefix  = sig_msg
sks = [nacl.signing.SigningKey(bytes(random.getrandbits(8) for _ in range(32))) for _ in range(k)]
pks = [sk.verify_key.encode().hex() for sk in sks]
json.dump(pks, open(f"{T}/kh.json", "w"))
entries = [(i, sks[i].sign(sig_msg).signature) for i in range(k)]
payload = prefix + bytes([len(entries)]) + b"".join(struct.pack("<H", i) + s for i, s in entries)
json.dump({"payload": payload.hex()}, open(f"{T}/assembled.json", "w"))
print(len(pks))
PY

build() {  # $1=name $2='--value N' or '--value-hex H' -> echoes built payload hex
  rm -f "$T/built.json"   # param-change-build refuses to overwrite an existing --out
  "$W" param-change-build $2 --name "$1" --effective-height 100 --nonce 0 --from node1 --out "$T/built.json" >/dev/null 2>&1
  $PY -c "import json;print(json.load(open('$T/built.json'))['payload'])"
}

echo "=== Scenario A: well-formed MIN_STAKE (8-byte) — build -> lint EFFECTIVE -> verify PASS ==="
BP=$(build MIN_STAKE "--value 1000")
"$W" param-change-lint --tx-json "$T/built.json" >/dev/null 2>&1
assert "$([ $? -eq 0 ] && echo true || echo false)" "A1: lint(built) -> EFFECTIVE exit 0"
$PY "$T/assemble.py" "$T" "$BP" 3 1 >/dev/null
# lint still EFFECTIVE on the assembled tx (sigs don't change name/value)
"$W" param-change-lint --tx-json "$T/assembled.json" >/dev/null 2>&1
assert "$([ $? -eq 0 ] && echo true || echo false)" "A2: lint(assembled) -> still EFFECTIVE (sigs don't affect effectiveness)"
set +e; "$W" param-change-verify --tx-json "$T/assembled.json" --keyholders "$T/kh.json" --threshold 3 >/dev/null 2>&1; RC=$?; set -e
assert "$([ $RC -eq 0 ] && echo true || echo false)" "A3: verify(assembled) -> PASS exit 0 (multisig valid)"

echo; echo "=== cross-command wire agreement: build's name/value reach lint AND verify ==="
LN=$("$W" param-change-lint --tx-json "$T/assembled.json" --json 2>/dev/null | $PY -c "import json,sys;print(json.load(sys.stdin)['name'])")
VN=$("$W" param-change-verify --tx-json "$T/assembled.json" --keyholders "$T/kh.json" --threshold 3 --json 2>/dev/null | $PY -c "import json,sys;print(json.load(sys.stdin)['name'])")
assert "$([ "$LN" = "MIN_STAKE" ] && [ "$VN" = "MIN_STAKE" ] && echo true || echo false)" "lint + verify both decode name=MIN_STAKE from the build payload"

echo; echo "=== Scenario B: the COMPLEMENTARITY trap — bad-width MIN_STAKE ==="
echo "    (lint catches the silent-no-op that a valid multisig cannot reveal)"
BP2=$(build MIN_STAKE "--value-hex 01020304")     # 4-byte value -> INERT at activation
set +e; "$W" param-change-lint --tx-json "$T/built.json" >/dev/null 2>&1; LRC=$?; set -e
assert "$([ $LRC -eq 2 ] && echo true || echo false)" "B1: lint(bad-width) -> INERT_BAD_WIDTH exit 2 (will silently no-op)"
$PY "$T/assemble.py" "$T" "$BP2" 3 2 >/dev/null
set +e; "$W" param-change-verify --tx-json "$T/assembled.json" --keyholders "$T/kh.json" --threshold 3 >/dev/null 2>&1; VRC=$?; set -e
assert "$([ $VRC -eq 0 ] && echo true || echo false)" "B2: verify(bad-width, valid sigs) -> PASS exit 0 (multisig is genuinely valid)"
assert "$([ $LRC -eq 2 ] && [ $VRC -eq 0 ] && echo true || echo false)" "B3: lint FAILs while verify PASSes -> the two checks are complementary"

echo; echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then echo "  PASS: test_wallet_param_change_flow"; exit 0
else echo "  FAIL: test_wallet_param_change_flow"; exit 1; fi
