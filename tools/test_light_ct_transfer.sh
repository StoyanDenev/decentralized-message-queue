#!/usr/bin/env bash
# CTX-2 confidential->confidential CLIENT loop: `determ-light build-ct-transfer`
# produces a submittable CONFIDENTIAL_TRANSFER (TxType 14) — a DCT1 bundle (m
# aggregated range proofs + a balance proof) — and `determ-light verify-ct-tx`
# re-runs the validator's DCT1 accept-rule (determ_ctx_bundle_verify + the
# tx.fee==bundle_fee check) over that exact JSON. Note-SET facts (inputs unspent)
# need pool state and are anchored by the committee-signed state_root, not this
# offline check. Pure offline. The multi-note sibling of test_light_ct_tx.sh.
#
# Assertions:
#   1. build-ct-transfer (1-in-1-out) writes a submittable CONFIDENTIAL_TRANSFER.
#   2. verify-ct-tx VERIFIES it (range + balance).
#   3. a 1-in-2-out (payment + change) transfer also builds + verifies.
#   4. a tampered payload byte -> verify-ct-tx INVALID (exit 3).
#   5. an UNBALANCED spec (Σin != Σout + fee) -> build error (exit 1).
#   6. determinism: same spec -> byte-identical payload.
#   7. a <32-byte nonce_seed -> build error.
#   8. >4 outputs -> build error (m*64 <= 256).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found"; exit 0; fi
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found (needed to mint a keyfile)"; exit 0; fi

TMP="build/test_light_ct_transfer.$$"; mkdir -p "$TMP"; trap 'rm -rf "$TMP"' EXIT
PY=python; command -v python >/dev/null 2>&1 || PY=python3
rc=0
pass(){ echo "  PASS: $1"; }
fail(){ echo "  FAIL: $1"; rc=1; }

"$DETERM_WALLET" account-create-batch --count 1 --out "$TMP/keys.json" >/dev/null 2>&1
$PY -c "import json,sys; json.dump(json.load(open(sys.argv[1]))['accounts'][0], open(sys.argv[2],'w'))" \
    "$TMP/keys.json" "$TMP/key.json"

S1=$(printf '11%.0s' $(seq 1 32)); S2=$(printf '22%.0s' $(seq 1 32))
S3=$(printf '33%.0s' $(seq 1 32)); NS=$(printf 'ab%.0s' $(seq 1 32))
SHORT=$(printf 'cd%.0s' $(seq 1 16))   # 16 bytes

# helper: write a spec file. args: outfile, python-dict-literal
spec(){ $PY -c "import json,sys; open(sys.argv[1],'w').write(sys.argv[2])" "$1" "$2"; }

# 1+2: 1-in-1-out (5 = 4 + fee 1).
spec "$TMP/s1.json" "{\"inputs\":[{\"value\":5,\"blind_seed\":\"$S1\"}],\"outputs\":[{\"value\":4,\"blind_seed\":\"$S2\"}],\"fee\":1,\"nonce_seed\":\"$NS\",\"tx_nonce\":0}"
if "$DETERM_LIGHT" build-ct-transfer --keyfile "$TMP/key.json" --spec "$TMP/s1.json" --out "$TMP/t1.json" >/dev/null 2>&1; then
  pass "build-ct-transfer (1-in-1-out) wrote a submittable CONFIDENTIAL_TRANSFER"
else fail "build-ct-transfer 1-in-1-out"; fi
if "$DETERM_LIGHT" verify-ct-tx --file "$TMP/t1.json" >/dev/null 2>&1; then
  pass "verify-ct-tx VERIFIED the DCT1 bundle (range + balance)"
else fail "verify-ct-tx rejected a valid CONFIDENTIAL_TRANSFER"; fi

# 3: 1-in-2-out (10 = 7 + 2 + fee 1).
spec "$TMP/s2.json" "{\"inputs\":[{\"value\":10,\"blind_seed\":\"$S1\"}],\"outputs\":[{\"value\":7,\"blind_seed\":\"$S2\"},{\"value\":2,\"blind_seed\":\"$S3\"}],\"fee\":1,\"nonce_seed\":\"$NS\",\"tx_nonce\":1}"
"$DETERM_LIGHT" build-ct-transfer --keyfile "$TMP/key.json" --spec "$TMP/s2.json" --out "$TMP/t2.json" >/dev/null 2>&1
if "$DETERM_LIGHT" verify-ct-tx --file "$TMP/t2.json" >/dev/null 2>&1; then
  pass "1-in-2-out (payment + change) builds + verifies"
else fail "1-in-2-out did not verify"; fi

# 4: tamper a payload byte -> INVALID.
$PY -c "
import json
d=json.load(open('$TMP/t1.json')); p=d['payload']; i=60; c='0' if p[i]!='0' else '1'
d['payload']=p[:i]+c+p[i+1:]; json.dump(d,open('$TMP/t1_bad.json','w'))"
"$DETERM_LIGHT" verify-ct-tx --file "$TMP/t1_bad.json" >/dev/null 2>&1
[ $? -eq 3 ] && pass "tampered payload -> INVALID (exit 3)" || fail "tampered payload not rejected"

# 5: unbalanced spec (5 != 3 + 1) -> build error.
spec "$TMP/s_bad.json" "{\"inputs\":[{\"value\":5,\"blind_seed\":\"$S1\"}],\"outputs\":[{\"value\":3,\"blind_seed\":\"$S2\"}],\"fee\":1,\"nonce_seed\":\"$NS\",\"tx_nonce\":0}"
if "$DETERM_LIGHT" build-ct-transfer --keyfile "$TMP/key.json" --spec "$TMP/s_bad.json" >/dev/null 2>&1; then
  fail "build-ct-transfer accepted an unbalanced spec"
else pass "unbalanced spec (Σin != Σout+fee) -> build error (exit 1)"; fi

# 6: determinism -> byte-identical payload.
"$DETERM_LIGHT" build-ct-transfer --keyfile "$TMP/key.json" --spec "$TMP/s1.json" --out "$TMP/t1b.json" >/dev/null 2>&1
P1=$($PY -c "import json;print(json.load(open('$TMP/t1.json'))['payload'])")
P2=$($PY -c "import json;print(json.load(open('$TMP/t1b.json'))['payload'])")
[ "$P1" = "$P2" ] && pass "deterministic: same spec -> byte-identical payload" || fail "non-deterministic payload"

# 7: short nonce_seed -> build error.
spec "$TMP/s_short.json" "{\"inputs\":[{\"value\":5,\"blind_seed\":\"$S1\"}],\"outputs\":[{\"value\":4,\"blind_seed\":\"$S2\"}],\"fee\":1,\"nonce_seed\":\"$SHORT\",\"tx_nonce\":0}"
if "$DETERM_LIGHT" build-ct-transfer --keyfile "$TMP/key.json" --spec "$TMP/s_short.json" >/dev/null 2>&1; then
  fail "build-ct-transfer accepted a 16-byte nonce_seed"
else pass "short nonce_seed -> build error (entropy floor)"; fi

# 8: 5 outputs -> build error (m not in {1,2,4}). balanced: 5 = 1*5, fee 0.
spec "$TMP/s_many.json" "{\"inputs\":[{\"value\":5,\"blind_seed\":\"$S1\"}],\"outputs\":[{\"value\":1,\"blind_seed\":\"$S2\"},{\"value\":1,\"blind_seed\":\"$S2\"},{\"value\":1,\"blind_seed\":\"$S2\"},{\"value\":1,\"blind_seed\":\"$S2\"},{\"value\":1,\"blind_seed\":\"$S2\"}],\"fee\":0,\"nonce_seed\":\"$NS\",\"tx_nonce\":0}"
if "$DETERM_LIGHT" build-ct-transfer --keyfile "$TMP/key.json" --spec "$TMP/s_many.json" >/dev/null 2>&1; then
  fail "build-ct-transfer accepted 5 outputs"
else pass "5 outputs -> build error (m must be 1, 2, or 4)"; fi

# 9: 3 outputs -> clean build error (m*64=192 is not a power of two — reject up front).
spec "$TMP/s3.json" "{\"inputs\":[{\"value\":6,\"blind_seed\":\"$S1\"}],\"outputs\":[{\"value\":2,\"blind_seed\":\"$S2\"},{\"value\":2,\"blind_seed\":\"$S2\"},{\"value\":2,\"blind_seed\":\"$S2\"}],\"fee\":0,\"nonce_seed\":\"$NS\",\"tx_nonce\":0}"
if "$DETERM_LIGHT" build-ct-transfer --keyfile "$TMP/key.json" --spec "$TMP/s3.json" >/dev/null 2>&1; then
  fail "build-ct-transfer accepted 3 outputs"
else pass "3 outputs -> clean build error (m must be a power-of-two dimension)"; fi

echo ""
if [ $rc -eq 0 ]; then echo "  PASS: confidential-transfer client loop"; else echo "  FAIL: ct-transfer e2e"; fi
exit $rc
