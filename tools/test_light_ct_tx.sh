#!/usr/bin/env bash
# CTX-2 confidential on/off-ramp CLIENT loop, CROSS-BINARY: `determ-light
# build-shield` / `build-unshield` produce a submittable SHIELD (TxType 12) /
# UNSHIELD (TxType 13), and `determ-light verify-ct-tx` re-runs the validator's
# CT accept-rule (determ_shield_verify / determ_unshield_verify) over that exact
# JSON — the same cryptographic gate a block validator applies. A tx this pair
# accepts is one a validator accepts (modulo transparent balance / pool state).
# Pure offline; no daemon. The CT sibling of test_light_audit_tx.sh.
#
# Assertions:
#   1. build-shield writes a submittable SHIELD (exit 0).
#   2. verify-ct-tx VERIFIES it (the SHIELD proof binds C to the public amount).
#   3. a tampered payload byte -> verify-ct-tx INVALID (exit 3).
#   4. changing the declared amount -> INVALID (C commits to the ORIGINAL amount).
#   5. build-unshield writes a submittable UNSHIELD that verify-ct-tx VERIFIES
#      (the context-bound proof — proof of the builder's ctx == the verifier's).
#   6. redirecting the recipient (--to) -> INVALID (front-running defense: the
#      bound proof's ctx no longer matches from/to/nonce/amount).
#   7. determinism: same (amount, blind-seed, ...) -> byte-identical payload.
#   8. amount 0 -> build-shield usage error (exit 1).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found"; exit 0; fi
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found (needed to mint a keyfile)"; exit 0; fi

TMP="build/test_light_ct_tx.$$"; mkdir -p "$TMP"; trap 'rm -rf "$TMP"' EXIT
PY=python; command -v python >/dev/null 2>&1 || PY=python3
rc=0
pass(){ echo "  PASS: $1"; }
fail(){ echo "  FAIL: $1"; rc=1; }

# Mint an anon keypair + canonical light keyfile.
"$DETERM_WALLET" account-create-batch --count 1 --out "$TMP/keys.json" >/dev/null 2>&1
$PY -c "import json,sys; json.dump(json.load(open(sys.argv[1]))['accounts'][0], open(sys.argv[2],'w'))" \
    "$TMP/keys.json" "$TMP/key.json"

SEED=$(printf 'aa%.0s' $(seq 1 32))
TO="0x$(printf 'b%.0s' $(seq 1 64))"
TO2="0x$(printf 'c%.0s' $(seq 1 64))"

# 1: build a SHIELD.
if "$DETERM_LIGHT" build-shield --keyfile "$TMP/key.json" --blind-seed "$SEED" \
     --amount 500 --fee 1 --nonce 0 --out "$TMP/shield.json" >/dev/null 2>&1; then
  pass "build-shield wrote a submittable SHIELD"
else fail "build-shield"; fi

# 2: the CT accept-rule verifies it.
if "$DETERM_LIGHT" verify-ct-tx --file "$TMP/shield.json" >/dev/null 2>&1; then
  pass "verify-ct-tx VERIFIED the SHIELD proof"
else fail "verify-ct-tx rejected a valid SHIELD"; fi

# 3: tamper one payload byte -> INVALID.
$PY -c "
import json,sys
d=json.load(open('$TMP/shield.json'))
p=d['payload']; i=40; c='0' if p[i]!='0' else '1'
d['payload']=p[:i]+c+p[i+1:]
json.dump(d,open('$TMP/shield_bad.json','w'))"
"$DETERM_LIGHT" verify-ct-tx --file "$TMP/shield_bad.json" >/dev/null 2>&1
[ $? -eq 3 ] && pass "tampered SHIELD payload -> INVALID (exit 3)" || fail "tampered payload not rejected"

# 4: change the declared amount -> INVALID (C commits to the original amount).
sed 's/"amount":500/"amount":501/' "$TMP/shield.json" > "$TMP/shield_amt.json"
"$DETERM_LIGHT" verify-ct-tx --file "$TMP/shield_amt.json" >/dev/null 2>&1
[ $? -eq 3 ] && pass "amount mismatch -> INVALID (proof binds the committed value)" || fail "amount tamper not rejected"

# 5: build + verify an UNSHIELD (context-bound proof).
"$DETERM_LIGHT" build-unshield --keyfile "$TMP/key.json" --blind-seed "$SEED" \
     --to "$TO" --amount 500 --fee 1 --nonce 0 --out "$TMP/unshield.json" >/dev/null 2>&1
if "$DETERM_LIGHT" verify-ct-tx --file "$TMP/unshield.json" >/dev/null 2>&1; then
  pass "build-unshield verifies (context-bound proof, builder ctx == verifier ctx)"
else fail "build-unshield did not verify"; fi

# 6: redirect the recipient -> INVALID (front-running defense).
sed "s/$TO/$TO2/" "$TMP/unshield.json" > "$TMP/unshield_redirect.json"
"$DETERM_LIGHT" verify-ct-tx --file "$TMP/unshield_redirect.json" >/dev/null 2>&1
[ $? -eq 3 ] && pass "recipient redirect -> INVALID (ctx rebind fails)" || fail "redirect not rejected"

# 7: determinism — same inputs -> byte-identical payload.
"$DETERM_LIGHT" build-shield --keyfile "$TMP/key.json" --blind-seed "$SEED" \
     --amount 500 --fee 1 --nonce 0 --out "$TMP/shield2.json" >/dev/null 2>&1
P1=$($PY -c "import json;print(json.load(open('$TMP/shield.json'))['payload'])")
P2=$($PY -c "import json;print(json.load(open('$TMP/shield2.json'))['payload'])")
[ "$P1" = "$P2" ] && pass "deterministic: same inputs -> byte-identical payload" || fail "non-deterministic payload"

# 8: amount 0 -> usage error.
if "$DETERM_LIGHT" build-shield --keyfile "$TMP/key.json" --blind-seed "$SEED" \
     --amount 0 --fee 1 --nonce 0 >/dev/null 2>&1; then
  fail "build-shield accepted amount 0"
else pass "build-shield rejects amount 0 (exit 1)"; fi

# 9: a short (<32-byte) blind-seed is refused (amount-privacy guard).
SHORT=$(printf 'aa%.0s' $(seq 1 16))   # 16 bytes
if "$DETERM_LIGHT" build-shield --keyfile "$TMP/key.json" --blind-seed "$SHORT" \
     --amount 500 --fee 1 --nonce 0 >/dev/null 2>&1; then
  fail "build-shield accepted a 16-byte blind-seed"
else pass "build-shield rejects a <32-byte blind-seed (entropy floor)"; fi

echo ""
if [ $rc -eq 0 ]; then echo "  PASS: confidential on/off-ramp client loop"; else echo "  FAIL: ct-tx e2e"; fi
exit $rc
