#!/usr/bin/env bash
# determ-wallet sign-anon-tx -> tx-sign-verify end-to-end tamper/impersonation edge.
#
# WHY THIS IS DISTINCT FROM THE EXISTING SUITE
# --------------------------------------------
#   * test_wallet_tx_sign_verify.sh  : tampers fields, but on tx envelopes
#       built by an INDEPENDENT Python Ed25519 signer (cryptography.hazmat),
#       NOT by the real sign-anon-tx command. Its from-tamper case flips one
#       hex char (still A's pubkey, just wrong) and verifies under A's key.
#   * test_wallet_tx_tamper_fuzz.sh   : single-field mutations, but routed
#       through `validate-tx`, which DERIVES the pubkey from the `from`
#       address — a structurally different gate than tx-sign-verify, which
#       takes --pubkey EXTERNALLY.
#   * test_wallet_sign_anon_tx.sh     : asserts only the HAPPY-path hand-off
#       (assertion 27) — sign-anon-tx envelope, shimmed (signature->sig,
#       "TRANSFER"->0), is ACCEPTED by tx-sign-verify. It never tampers the
#       envelope after signing, and never tests impersonation.
#
# This test closes the genuinely uncovered corner: take a REAL sign-anon-tx
# envelope from account A and prove the address<->pubkey binding in
# signing_bytes is sound against an IMPERSONATION attacker who rewrites the
# `from` address to a *different real account* B and presents B's own pubkey
# (the most plausible "claim this tx came from B" forgery), plus
# post-signing single-field mutations driven through the real signer->
# verifier path. Every forgery MUST be rejected with exit 2 (auth-style
# alert), while the untouched envelope verifies with exit 0.
#
# The security property under test (fail-closed):
#   sign-anon-tx binds `from` (= signer's anon address = signer's Ed25519
#   pubkey) into the canonical signing_bytes. Therefore NO substitution of
#   `from`, `to`, `amount`, or `nonce` — and no swap of the verifying
#   pubkey — can make a doctored envelope verify. If any of these RED-line
#   forgeries returned exit 0, the binary would be fail-OPEN (accepting a
#   forged/impersonated tx) — a critical defect.
#
# Fully OFFLINE: no daemon, no RPC, no network. Cleans up its temp dir.
# Exit 0 = all assertions pass; exit 1 = at least one failed.
#
# Run from repo root: bash tools/test_wallet_sign_anon_tx_verify_tamper_edge.sh
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

TMP="build/test_wallet_sign_anon_tx_verify_tamper_edge.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT INT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}

# ── Two fresh real keypairs: A is the signer, B is a second real account ──────
"$W" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
if [ ! -s "$TMP/keys.json" ]; then
  echo "  SKIP: account-create-batch produced no keys (cannot run)"; exit 0
fi
PRIV_A=$($PY -c "import json;print(json.load(open('$TMP/keys.json'))['accounts'][0]['privkey_hex'])")
ADDR_A=$($PY -c "import json;print(json.load(open('$TMP/keys.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json;print(json.load(open('$TMP/keys.json'))['accounts'][1]['address'])")
PUB_A="${ADDR_A#0x}"     # anon address == 0x + 64-hex Ed25519 pubkey
PUB_B="${ADDR_B#0x}"

cat > "$TMP/key_a.json" <<EOF
{"address":"$ADDR_A","privkey_hex":"$PRIV_A"}
EOF

# ── Sign a REAL TRANSFER A -> B with the production signer ────────────────────
"$W" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" \
     --amount 1000 --fee 5 --nonce 3 --out "$TMP/signed.json" >/dev/null 2>&1
if [ ! -s "$TMP/signed.json" ]; then
  echo "  FAIL: sign-anon-tx produced no envelope; cannot run edge test"
  echo "  FAIL: test_wallet_sign_anon_tx_verify_tamper_edge"; exit 1
fi

# sign-anon-tx emits the signature under "signature" and type as the mnemonic
# "TRANSFER"; tx-sign-verify needs numeric type=0 + field name "sig". Build a
# verify-shaped copy WITHOUT altering any consensus-bound field. From here all
# mutations operate on this faithful copy so the only variable is the tamper.
$PY - "$TMP/signed.json" "$TMP/base.json" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
d = json.load(open(src))
out = dict(d)
out["type"] = 0                       # mnemonic -> numeric TxType TRANSFER
out["sig"]  = d["signature"]          # field-name shim; value identical
json.dump(out, open(dst, "w"))
PY

vrun() {  # vrun <tx-json> <pubkey> -> echoes the exit code of tx-sign-verify
  set +e
  "$W" tx-sign-verify --tx "$1" --pubkey "$2" >/dev/null 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

echo "=== signed envelope field set ==="
$PY -c "import json;print(sorted(json.load(open('$TMP/signed.json')).keys()))"

echo
echo "=== A. CONTROL: untouched real envelope verifies under signer A's pubkey (exit 0) ==="
assert_eq "$(vrun "$TMP/base.json" "$PUB_A")" "0" \
  "untouched sign-anon-tx envelope VALIDATES under A's pubkey"

echo
echo "=== B. IMPERSONATION (the headline RED candidate): rewrite from=B, verify under B's OWN pubkey -> exit 2 ==="
# An attacker who controls account B's keypair takes A's signed tx and tries
# to pass it off as authored by B: they swap the `from` address to B's
# address and present B's own pubkey. `from` is bound in signing_bytes, so
# A's signature cannot validate under B's pubkey over the B-claimed body.
# If this returned 0 the binary would accept a forged authorship claim.
$PY - "$TMP/base.json" "$TMP/imp.json" "$ADDR_B" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["from"] = sys.argv[3]               # claim authorship as account B
json.dump(d, open(sys.argv[2], "w"))
PY
assert_eq "$(vrun "$TMP/imp.json" "$PUB_B")" "2" \
  "from-swapped-to-B envelope is REJECTED under B's own pubkey (no impersonation)"

echo
echo "=== C. from-swapped-to-B but verified under A's pubkey -> exit 2 ==="
# The same body, but the verifier still uses A's pubkey: the signed body had
# from=A, so changing from to B breaks the message A signed.
assert_eq "$(vrun "$TMP/imp.json" "$PUB_A")" "2" \
  "from-swapped envelope is REJECTED under A's pubkey (body no longer matches sig)"

echo
echo "=== D. recipient redirect: to=A (steal funds back to signer) -> exit 2 ==="
$PY - "$TMP/base.json" "$TMP/to.json" "$ADDR_A" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["to"] = sys.argv[3]
json.dump(d, open(sys.argv[2], "w"))
PY
assert_eq "$(vrun "$TMP/to.json" "$PUB_A")" "2" \
  "recipient redirect (to=A) is REJECTED"

echo
echo "=== E. amount inflation: amount+1 -> exit 2 ==="
$PY - "$TMP/base.json" "$TMP/amt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["amount"] = int(d["amount"]) + 1
json.dump(d, open(sys.argv[2], "w"))
PY
assert_eq "$(vrun "$TMP/amt.json" "$PUB_A")" "2" \
  "amount inflation (amount+1) is REJECTED"

echo
echo "=== F. nonce bump (replay-position shift): nonce+1 -> exit 2 ==="
$PY - "$TMP/base.json" "$TMP/nonce.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["nonce"] = int(d["nonce"]) + 1
json.dump(d, open(sys.argv[2], "w"))
PY
assert_eq "$(vrun "$TMP/nonce.json" "$PUB_A")" "2" \
  "nonce bump (nonce+1) is REJECTED"

echo
echo "=== G. fee tamper: fee+1 -> exit 2 ==="
$PY - "$TMP/base.json" "$TMP/fee.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["fee"] = int(d["fee"]) + 1
json.dump(d, open(sys.argv[2], "w"))
PY
assert_eq "$(vrun "$TMP/fee.json" "$PUB_A")" "2" \
  "fee tamper (fee+1) is REJECTED"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_wallet_sign_anon_tx_verify_tamper_edge"; exit 0
else
  echo "  FAIL: test_wallet_sign_anon_tx_verify_tamper_edge"; exit 1
fi
