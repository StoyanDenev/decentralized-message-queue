#!/usr/bin/env bash
# A2 audit-layer CLIENT→CONSENSUS loop, CROSS-BINARY: `determ-light
# rotate-audit-key` / `log-audit-access` build canonical, submittable
# ROTATE_AUDIT_KEY (TxType 15) / LOG_AUDIT_ACCESS (TxType 16) transactions
# (account-Ed25519-signed, fee-only), and `determ verify-audit-tx` applies the
# validator's anon-account accept-check (anon-sig + shape gate) to that exact
# JSON — the same rule the block validator runs (src/node/validator.cpp:603-623
# + the shape gates in src/chain/chain.cpp). A tx this pair accepts is one a
# validator accepts. Pure offline; no daemon. Mirrors test_pq_transfer_e2e.sh
# for the Ed25519 (anon) audit path.
#
# Assertions:
#   1. rotate-audit-key --pubkey writes a submittable ROTATE_AUDIT_KEY (exit 0).
#   2. verify-audit-tx VERIFIES it (exit 0) — the consensus check accepts.
#   3. rotate-audit-key --clear (revoke, empty payload) also verifies.
#   4. log-audit-access writes a submittable LOG_AUDIT_ACCESS that verifies.
#   5. tampering the fee -> verify-audit-tx INVALID (exit 3) (sig binds the fee).
#   6. --pubkey and --clear together are refused by rotate-audit-key (exit 1).
#   7. a non-audit tx (TRANSFER) -> verify-audit-tx INVALID (exit 3).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found"; exit 0; fi
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found (needed to mint a keyfile)"; exit 0; fi
if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found (needed for verify-audit-tx)"; exit 0; fi

TMP="build/test_light_audit_tx.$$"; mkdir -p "$TMP"; trap 'rm -rf "$TMP"' EXIT
PY=python; command -v python >/dev/null 2>&1 || PY=python3
rc=0
pass(){ echo "  PASS: $1"; }
fail(){ echo "  FAIL: $1"; rc=1; }

# Mint an anon keypair + write a canonical light keyfile ({address,privkey_hex}).
"$DETERM_WALLET" account-create-batch --count 1 --out "$TMP/keys.json" >/dev/null 2>&1
$PY -c "import json,sys; json.dump(json.load(open(sys.argv[1]))['accounts'][0], open(sys.argv[2],'w'))" \
    "$TMP/keys.json" "$TMP/key.json"

# Fixed 32-byte hex operands for the payloads.
PUBKEY=$(printf 'a1%.0s' $(seq 1 32))
AUDITOR=$(printf 'b2%.0s' $(seq 1 32))
CONTEXT=$(printf 'c3%.0s' $(seq 1 32))

# 1: build a ROTATE_AUDIT_KEY (set form).
if "$DETERM_LIGHT" rotate-audit-key --keyfile "$TMP/key.json" --pubkey "$PUBKEY" \
     --fee 1 --nonce 0 --out "$TMP/rot.json" >/dev/null 2>&1; then
  pass "rotate-audit-key --pubkey wrote a submittable ROTATE_AUDIT_KEY"
else fail "rotate-audit-key --pubkey"; fi

# 2: the audit accept-check (in the full binary) accepts it.
if "$DETERM" verify-audit-tx --file "$TMP/rot.json" >/dev/null 2>&1; then
  pass "verify-audit-tx VERIFIED ROTATE_AUDIT_KEY (consensus check accepts)"
else fail "verify-audit-tx rejected a valid ROTATE_AUDIT_KEY"; fi

# 3: the clear (revoke) form — empty payload — also verifies.
"$DETERM_LIGHT" rotate-audit-key --keyfile "$TMP/key.json" --clear \
     --fee 1 --nonce 0 --out "$TMP/clr.json" >/dev/null 2>&1
if "$DETERM" verify-audit-tx --file "$TMP/clr.json" >/dev/null 2>&1; then
  pass "rotate-audit-key --clear verifies (empty-payload revoke)"
else fail "rotate-audit-key --clear did not verify"; fi

# 4: LOG_AUDIT_ACCESS (72-byte payload: epoch || auditor || context).
"$DETERM_LIGHT" log-audit-access --keyfile "$TMP/key.json" --epoch 7 \
     --auditor "$AUDITOR" --context "$CONTEXT" --fee 1 --nonce 0 \
     --out "$TMP/log.json" >/dev/null 2>&1
if "$DETERM" verify-audit-tx --file "$TMP/log.json" >/dev/null 2>&1; then
  pass "log-audit-access verifies (72-byte disclosure record)"
else fail "log-audit-access did not verify"; fi

# 5: tamper the fee -> INVALID (the Ed25519 sig binds fee via signing_bytes).
# write_json_file emits compact JSON (no space after the colon).
sed 's/"fee":1/"fee":2/' "$TMP/rot.json" > "$TMP/bad.json"
"$DETERM" verify-audit-tx --file "$TMP/bad.json" >/dev/null 2>&1
if [ $? -eq 3 ]; then pass "tampered fee -> INVALID (exit 3)"; else fail "tamper not rejected"; fi

# 6: --pubkey and --clear together are a usage error.
if "$DETERM_LIGHT" rotate-audit-key --keyfile "$TMP/key.json" --pubkey "$PUBKEY" \
     --clear --fee 1 --nonce 0 >/dev/null 2>&1; then
  fail "rotate-audit-key accepted both --pubkey and --clear"
else pass "rotate-audit-key refuses --pubkey + --clear together (exit 1)"; fi

# 7: a non-audit tx (plain TRANSFER) is not an audit tx -> INVALID.
ADDR=$($PY -c "import json; print(json.load(open('$TMP/key.json'))['address'])")
"$DETERM_LIGHT" sign-tx --keyfile "$TMP/key.json" --type TRANSFER --to "$ADDR" \
     --amount 1 --fee 0 --nonce 0 --out "$TMP/xfer.json" >/dev/null 2>&1
"$DETERM" verify-audit-tx --file "$TMP/xfer.json" >/dev/null 2>&1
if [ $? -eq 3 ]; then pass "TRANSFER -> verify-audit-tx INVALID (type gate)"; else fail "TRANSFER not rejected by type gate"; fi

echo ""
if [ $rc -eq 0 ]; then echo "  PASS: audit-layer client->consensus loop"; else echo "  FAIL: audit-tx e2e"; fi
exit $rc
